//! Opens KMS's `CiphertextForRecipient`: a CMS `EnvelopedData` (RFC 5652)
//! with one recipient, its key wrapped with RSAES-OAEP (SHA-256) to the
//! public key the guest put in its attestation document, its content
//! AES-256-CBC. Only that shape is read; any other is refused.
//!
//! The walk takes BER, since CMS producers may write indefinite lengths
//! and chunked octet strings, and it is schema-directed and bounded: no
//! recursion, a depth limit for what it skips, every length checked
//! against the input before it is used.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use rsa::{Oaep, RsaPrivateKey};
use thiserror::Error;

use crate::protocol::CMS_BYTES_MAX;

/// What KMS's key wraps: an AES-256 key.
pub const CONTENT_KEY_BYTES: usize = 32;
pub const IV_BYTES: usize = 16;
/// An RSA-4096 key's wrap, the largest we would make.
pub const WRAPPED_KEY_BYTES_MAX: usize = 512;
/// KMS's plaintext limit (4096 bytes) padded to the next block.
pub const CIPHERTEXT_BYTES_MAX: usize = 4096 + IV_BYTES;
/// Pieces of a chunked octet string.
pub const CHUNKS_MAX: usize = 64;
/// How deep a skipped element may nest.
pub const DEPTH_MAX: usize = 16;

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;
const OCTET_STRING_CHUNKED: u8 = 0x24;
const OID: u8 = 0x06;
const CONTEXT_0: u8 = 0xa0;
const CONTEXT_0_PRIMITIVE: u8 = 0x80;
const CONTEXT_1: u8 = 0xa1;
/// 1.2.840.113549.1.7.3, 1.2.840.113549.1.7.1, 1.2.840.113549.1.1.7 and
/// 2.16.840.1.101.3.4.1.42, as their DER content.
const OID_ENVELOPED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03];
const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const OID_RSAES_OAEP: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07];
const OID_AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CmsError {
    #[error("an envelope of {0} bytes, over {CMS_BYTES_MAX}")]
    TooLarge(usize),
    #[error("malformed BER at byte {0}")]
    Malformed(usize),
    #[error("at byte {at}: expected tag {expected:#04x}, found {found:#04x}")]
    Tag { at: usize, expected: u8, found: u8 },
    #[error("not the envelope KMS sends: {0}")]
    Shape(&'static str),
    #[error("the wrapped key does not open with this key")]
    Unwrap,
    #[error("the content does not decrypt (wrong key or padding)")]
    Content,
}

/// An element's length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Len {
    Definite(usize),
    Indefinite,
}

/// A constructed element being read: where it ends, or that it ends at an
/// end-of-contents marker.
struct Frame {
    end: Option<usize>,
}

struct Ber<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Ber<'a> {
    fn header(&mut self) -> Result<(u8, Len), CmsError> {
        let start = self.at;
        let tag = *self.b.get(self.at).ok_or(CmsError::Malformed(start))?;
        if tag & 0x1f == 0x1f {
            return Err(CmsError::Malformed(start));
        }
        let first = *self.b.get(self.at + 1).ok_or(CmsError::Malformed(start))?;
        self.at += 2;
        let len = if first == 0x80 {
            // Only constructed elements may be indefinite.
            if tag & 0x20 == 0 {
                return Err(CmsError::Malformed(start));
            }
            Len::Indefinite
        } else if first < 0x80 {
            Len::Definite(usize::from(first))
        } else {
            let n = usize::from(first & 0x7f);
            if n > 3 {
                return Err(CmsError::Malformed(start));
            }
            let bytes = self.b.get(self.at..self.at + n).ok_or(CmsError::Malformed(start))?;
            self.at += n;
            Len::Definite(bytes.iter().fold(0usize, |v, b| (v << 8) | usize::from(*b)))
        };
        if let Len::Definite(n) = len {
            if n > self.b.len() - self.at {
                return Err(CmsError::Malformed(start));
            }
        }
        Ok((tag, len))
    }

    fn peek_tag(&self) -> Option<u8> {
        self.b.get(self.at).copied()
    }

    fn at_eoc(&self) -> bool {
        self.b.get(self.at..self.at + 2) == Some(&[0, 0])
    }

    fn enter(&mut self, expected: u8) -> Result<Frame, CmsError> {
        let at = self.at;
        let (tag, len) = self.header()?;
        if tag != expected {
            return Err(CmsError::Tag { at, expected, found: tag });
        }
        Ok(Frame { end: match len {
            Len::Definite(n) => Some(self.at + n),
            Len::Indefinite => None,
        } })
    }

    /// Whether `frame` has more children.
    fn more(&self, frame: &Frame) -> bool {
        match frame.end {
            Some(end) => self.at < end,
            None => !self.at_eoc(),
        }
    }

    fn leave(&mut self, frame: Frame) -> Result<(), CmsError> {
        match frame.end {
            Some(end) if self.at == end => Ok(()),
            Some(_) => Err(CmsError::Malformed(self.at)),
            None if self.at_eoc() => {
                self.at += 2;
                Ok(())
            }
            None => Err(CmsError::Malformed(self.at)),
        }
    }

    fn primitive(&mut self, expected: u8) -> Result<&'a [u8], CmsError> {
        let at = self.at;
        let (tag, len) = self.header()?;
        if tag != expected {
            return Err(CmsError::Tag { at, expected, found: tag });
        }
        let Len::Definite(n) = len else { return Err(CmsError::Malformed(at)) };
        let s = &self.b[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }

    /// An octet string, plain or chunked, under `primitive_tag` or
    /// `chunked_tag`; at most `max` bytes in all.
    fn octets(&mut self, primitive_tag: u8, chunked_tag: u8, max: usize) -> Result<Vec<u8>, CmsError> {
        let at = self.at;
        let out = match self.peek_tag() {
            Some(t) if t == primitive_tag => self.primitive(primitive_tag)?.to_vec(),
            Some(t) if t == chunked_tag => {
                let frame = self.enter(chunked_tag)?;
                let mut out = Vec::new();
                let mut chunks = 0;
                while self.more(&frame) {
                    chunks += 1;
                    if chunks > CHUNKS_MAX {
                        return Err(CmsError::Shape("too many chunks"));
                    }
                    out.extend_from_slice(self.primitive(OCTET_STRING)?);
                    if out.len() > max {
                        break;
                    }
                }
                self.leave(frame)?;
                out
            }
            Some(found) => return Err(CmsError::Tag { at, expected: primitive_tag, found }),
            None => return Err(CmsError::Malformed(at)),
        };
        if out.len() > max {
            return Err(CmsError::Shape("an octet string over its limit"));
        }
        Ok(out)
    }

    /// Skips one element, nested indefinite ones included, iteratively.
    fn skip(&mut self) -> Result<(), CmsError> {
        // Open indefinite elements still to close; definite ones are
        // stepped over whole.
        let mut open = 0usize;
        loop {
            if open > 0 && self.at_eoc() {
                self.at += 2;
                open -= 1;
                if open == 0 {
                    return Ok(());
                }
                continue;
            }
            let (_, len) = self.header()?;
            match len {
                Len::Definite(n) => self.at += n,
                Len::Indefinite => {
                    open += 1;
                    if open > DEPTH_MAX {
                        return Err(CmsError::Shape("nested too deep"));
                    }
                }
            }
            if open == 0 {
                return Ok(());
            }
        }
    }
}

/// The three things an envelope carries for us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub wrapped_key: Vec<u8>,
    pub iv: [u8; IV_BYTES],
    pub ciphertext: Vec<u8>,
}

pub fn parse(ber: &[u8]) -> Result<Envelope, CmsError> {
    if ber.len() > CMS_BYTES_MAX {
        return Err(CmsError::TooLarge(ber.len()));
    }
    let mut r = Ber { b: ber, at: 0 };
    let content_info = r.enter(SEQUENCE)?;
    if r.primitive(OID)? != OID_ENVELOPED_DATA {
        return Err(CmsError::Shape("not EnvelopedData"));
    }
    let explicit = r.enter(CONTEXT_0)?;
    let enveloped = r.enter(SEQUENCE)?;
    r.primitive(INTEGER)?; // version
    if r.peek_tag() == Some(CONTEXT_0) {
        r.skip()?; // originatorInfo
    }
    let recipients = r.enter(SET)?;
    let recipient = r.enter(SEQUENCE)?;
    r.primitive(INTEGER)?; // version
    r.skip()?; // rid: issuerAndSerialNumber or subjectKeyIdentifier
    let algorithm = r.enter(SEQUENCE)?;
    if r.primitive(OID)? != OID_RSAES_OAEP {
        return Err(CmsError::Shape("the key is not wrapped with RSAES-OAEP"));
    }
    // The parameters name SHA-256; a wrap under any other hash fails to
    // open below, which is the check that matters.
    while r.more(&algorithm) {
        r.skip()?;
    }
    r.leave(algorithm)?;
    let wrapped_key = r.octets(OCTET_STRING, OCTET_STRING_CHUNKED, WRAPPED_KEY_BYTES_MAX)?;
    r.leave(recipient)?;
    if r.more(&recipients) {
        return Err(CmsError::Shape("more than one recipient"));
    }
    r.leave(recipients)?;
    let content = r.enter(SEQUENCE)?;
    if r.primitive(OID)? != OID_DATA {
        return Err(CmsError::Shape("the content is not data"));
    }
    let cipher = r.enter(SEQUENCE)?;
    if r.primitive(OID)? != OID_AES256_CBC {
        return Err(CmsError::Shape("the content is not AES-256-CBC"));
    }
    let iv: [u8; IV_BYTES] = r.primitive(OCTET_STRING)?.try_into().map_err(|_| CmsError::Shape("an IV that is not 16 bytes"))?;
    r.leave(cipher)?;
    let ciphertext = r.octets(CONTEXT_0_PRIMITIVE, CONTEXT_0, CIPHERTEXT_BYTES_MAX)?;
    r.leave(content)?;
    if r.peek_tag() == Some(CONTEXT_1) {
        r.skip()?; // unprotectedAttrs
    }
    r.leave(enveloped)?;
    r.leave(explicit)?;
    r.leave(content_info)?;
    if r.at != ber.len() {
        return Err(CmsError::Malformed(r.at));
    }
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(IV_BYTES) {
        return Err(CmsError::Shape("a ciphertext that is not whole blocks"));
    }
    Ok(Envelope { wrapped_key, iv, ciphertext })
}

/// Opens an envelope with `key`: the plaintext, or why not.
pub fn open(key: &RsaPrivateKey, ber: &[u8]) -> Result<Vec<u8>, CmsError> {
    let e = parse(ber)?;
    let content_key = key.decrypt(Oaep::new::<sha2::Sha256>(), &e.wrapped_key).map_err(|_| CmsError::Unwrap)?;
    if content_key.len() != CONTENT_KEY_BYTES {
        return Err(CmsError::Shape("the content key is not AES-256's"));
    }
    let decryptor = cbc::Decryptor::<aes::Aes256>::new_from_slices(&content_key, &e.iv).map_err(|_| CmsError::Content)?;
    let plaintext = decryptor.decrypt_padded_vec_mut::<Pkcs7>(&e.ciphertext).map_err(|_| CmsError::Content)?;
    assert!(plaintext.len() < e.ciphertext.len(), "PKCS#7 removes at least one byte");
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::DecodePrivateKey;

    // Test vectors made with OpenSSL on the spike's parent (tests/vectors/
    // README.md says how): a TEST-ONLY RSA-2048 key, and one plaintext
    // sealed to it twice, as DER and as streamed BER (indefinite lengths,
    // chunked content). Independent of this code, so the walk is held to
    // another implementation's output, not its own.
    const KEY: &str = include_str!("../tests/vectors/test-only-key.pem");
    const DER: &[u8] = include_bytes!("../tests/vectors/sealed.der");
    const BER: &[u8] = include_bytes!("../tests/vectors/sealed-streamed.ber");
    const PLAINTEXT: &[u8] = include_bytes!("../tests/vectors/plaintext.bin");

    fn key() -> RsaPrivateKey {
        RsaPrivateKey::from_pkcs8_pem(KEY).expect("the test key")
    }

    // Goal: what OpenSSL seals, we open, in both encodings.
    #[test]
    fn opens_openssls_envelopes() {
        assert_eq!(open(&key(), DER).unwrap(), PLAINTEXT);
        assert_eq!(open(&key(), BER).unwrap(), PLAINTEXT);
        assert!(BER.windows(2).any(|w| w == [0x30, 0x80]), "the streamed vector really is indefinite");
    }

    // Goal: no cut gets past the walk, and no changed byte of what is
    // opened (the wrapped key, the IV, the ciphertext) gives the
    // plaintext back. Method: every prefix of both; a bit flipped at
    // every byte of those three in the DER one.
    //
    // Why only those three: CMS authenticates nothing. A flip in a field
    // the walk skips (the recipient's id, the OAEP parameters) still
    // opens; a flip in the IV or a cipher block changes the plaintext
    // instead of failing (CBC's nature). And anyone, the parent included,
    // can seal an envelope to the public key a document carries. So a
    // guest trusts what KMS released only by how it uses it (a disk key
    // that opens the disk's own seals), or by calling KMS over TLS it
    // ends itself: docs/nitro-spike.md, acceptance 5's results.
    #[test]
    fn cut_or_changed_envelopes_refused() {
        for v in [DER, BER] {
            for cut in 0..v.len() {
                assert!(parse(&v[..cut]).is_err(), "cut at {cut}");
            }
        }
        let e = parse(DER).unwrap();
        let find = |needle: &[u8]| DER.windows(needle.len()).position(|w| w == needle).expect("in the envelope");
        let regions = [(find(&e.wrapped_key), e.wrapped_key.len()), (find(&e.iv), IV_BYTES), (find(&e.ciphertext), e.ciphertext.len())];
        let k = key();
        let mut flipped = 0;
        for (start, len) in regions {
            for i in start..start + len {
                let mut c = DER.to_vec();
                c[i] ^= 0x01;
                if let Ok(p) = open(&k, &c) {
                    assert_ne!(p, PLAINTEXT, "byte {i} changed, and the same plaintext came out");
                }
                flipped += 1;
            }
        }
        assert!(flipped > 256 + IV_BYTES, "the whole wrap and more");
        let mut oid = DER.to_vec();
        let at = find(OID_AES256_CBC);
        oid[at + OID_AES256_CBC.len() - 1] ^= 0x01;
        assert_eq!(open(&k, &oid), Err(CmsError::Shape("the content is not AES-256-CBC")));
    }

    // Goal: another key cannot open it.
    #[test]
    fn another_key_cannot_open() {
        let other = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        assert_eq!(open(&other, DER), Err(CmsError::Unwrap));
    }

    // Goal: the walk's limits. Method: an oversized envelope; a skip past
    // its depth limit.
    #[test]
    fn limits() {
        assert_eq!(parse(&vec![0x30; CMS_BYTES_MAX + 1]), Err(CmsError::TooLarge(CMS_BYTES_MAX + 1)));
        let deep: Vec<u8> = std::iter::repeat_n([0x30u8, 0x80], DEPTH_MAX + 1).flatten().collect();
        let mut r = Ber { b: &deep, at: 0 };
        assert_eq!(r.skip(), Err(CmsError::Shape("nested too deep")));
    }
}
