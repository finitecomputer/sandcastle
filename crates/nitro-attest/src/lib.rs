//! Verifies an AWS Nitro attestation document: what a Nitro Enclave, or a
//! Nitro Sandbox in confidential mode, gets from its Nitro Security Module
//! (`/dev/nsm`) to prove which image it runs on which parent
//! (docs/nitro-spike.md, acceptance 4). Written to become celld's verifier,
//! so it is pure: the caller passes the time, and the nonce ledger takes
//! its randomness from the caller.
//!
//! The checks, in order (AWS's "Verifying the root of trust", and
//! `docs/attestation_process.md` of aws-nitro-enclaves-nsm-api, 3.2.2 to
//! 3.2.4):
//!
//! 1. **The envelope**: a COSE_Sign1 (CBOR tag 18 or bare), four items; the
//!    protected header exactly `{1: -35}` (ES384); the unprotected header
//!    empty; the signature 96 bytes (P-384's r and s).
//! 2. **The payload**: a map of the nine known fields, each typed and
//!    bounded, the six mandatory ones present, none repeated, none unknown;
//!    the digest `SHA384`, so every PCR is 48 bytes.
//! 3. **The chain**: the bundle's first certificate is the pinned root,
//!    byte for byte, and the root is within its validity; the signing
//!    certificate chains to it through the rest of the bundle (webpki:
//!    signatures, basic constraints, path lengths, validity at the given
//!    time); the signing certificate has `digitalSignature`.
//! 4. **The signature**: ES384 over COSE's `Sig_structure`, by the signing
//!    certificate's key.
//! 5. **Freshness**: the document's own time at most [`AGE_MS_MAX`] old and
//!    at most [`SKEW_MS_MAX`] ahead.
//! 6. **The nonce**: the caller's, exactly; or, through [`Nonces`], one this
//!    verifier issued, still live, and never used before.
//!
//! What it does not check: the PCRs. Which image is acceptable is the
//! caller's policy; [`Attested`] hands them over.

mod cbor;
mod chain;
mod der;
mod document;
mod nonce;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod testkit;

pub use cbor::{CborFault, Kind};
pub use chain::{Trust, AWS_ROOT_G1_SHA256};
pub use der::DerFault;
pub use document::{CoseFault, Field, FieldFault};
pub use nonce::{IssueError, Nonce, Nonces, NONCES_OUTSTANDING_MAX, NONCE_BYTES, NONCE_LIFE_MS};
// Callers match chain errors by webpki's own variants.
pub use webpki;

use thiserror::Error;

/// A whole document, envelope included. AWS's documents are about 4.5 KiB;
/// the payload alone may be 16 KiB (below), the certificates 1 KiB each.
pub const DOCUMENT_BYTES_MAX: usize = 32 * 1024;
/// The COSE payload: `bstr .size (1..16384)` (attestation_process.md).
pub const PAYLOAD_BYTES_MAX: usize = 16 * 1024;
/// A certificate, the signing one or one in the bundle: `bytes .size (1..1024)`.
pub const CERTIFICATE_BYTES_MAX: usize = 1024;
/// Certificates in the bundle. AWS's chains are a root and three
/// intermediates; eight leaves room without letting a bundle grow.
pub const CABUNDLE_LEN_MAX: u64 = 8;
/// PCRs a document lists: indexes 0 to 31.
pub const PCRS_MAX: u64 = 32;
/// A PCR under SHA-384.
pub const PCR_BYTES: usize = 48;
/// The module's id: non-empty text. AWS's are an instance id and an
/// enclave id, under 64 bytes.
pub const MODULE_ID_BYTES_MAX: usize = 256;
/// The optional public key: `bytes .size (1..1024)`.
pub const PUBLIC_KEY_BYTES_MAX: usize = 1024;
/// The optional user data and nonce. AWS's guide says 1024 bytes and the
/// NSM's process document 512; the larger is accepted, since the NSM
/// enforces its own limit when it signs.
pub const USER_DATA_BYTES_MAX: usize = 1024;
pub const NONCE_FIELD_BYTES_MAX: usize = 1024;
/// ES384's signature: r and s, 48 bytes each.
pub const SIGNATURE_BYTES: usize = 96;
/// How old a document may be. The NSM dates it when it signs; a verifier
/// that asked with a nonce expects it within one exchange.
pub const AGE_MS_MAX: u64 = 5 * 60 * 1000;
/// How far ahead of the verifier's clock a document may be dated.
pub const SKEW_MS_MAX: u64 = 60 * 1000;

const _: () = assert!(PAYLOAD_BYTES_MAX < DOCUMENT_BYTES_MAX);
const _: () = assert!(CERTIFICATE_BYTES_MAX * (CABUNDLE_LEN_MAX as usize + 1) < PAYLOAD_BYTES_MAX);
const _: () = assert!(SKEW_MS_MAX < AGE_MS_MAX);

/// Why a document is refused. Every check has its own variant, so a caller
/// (and a test) can tell which one failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AttestError {
    #[error("the document is {len} bytes, over {max}")]
    TooLarge { len: usize, max: usize },
    #[error("malformed CBOR at byte {at}: {fault}")]
    Cbor { at: usize, fault: CborFault },
    #[error("the COSE envelope: {0}")]
    Cose(CoseFault),
    #[error("the payload's {field}: {fault}")]
    Field { field: Field, fault: FieldFault },
    #[error("the bundle's first certificate is not the trusted root")]
    RootNotPinned,
    #[error("the trusted root is outside its validity at this time")]
    RootNotValidNow,
    #[error("the certificate chain: {0}")]
    Chain(webpki::Error),
    #[error("a certificate's DER: {0}")]
    Der(DerFault),
    #[error("the signing certificate's key usage lacks digitalSignature")]
    LeafKeyUsage,
    #[error("the COSE signature does not verify")]
    Signature,
    #[error("the document is {age_ms} ms old, over {max_ms}")]
    Stale { age_ms: u64, max_ms: u64 },
    #[error("the document is dated {ahead_ms} ms ahead of this clock")]
    FromTheFuture { ahead_ms: u64 },
    #[error("the document carries no nonce")]
    NonceMissing,
    #[error("the document's nonce is not the one expected")]
    NonceMismatch,
    #[error("the document's nonce was never issued here, or was already used")]
    NonceUnknown,
    #[error("the document's nonce outlived its life")]
    NonceExpired,
}

/// What a verified document says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    /// The NSM's id: the parent's instance and the enclave. Not secret, but
    /// it names the instance, so evidence that leaves the project redacts it.
    pub module_id: String,
    /// When the NSM signed, in milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// Each PCR the document lists, by ascending index.
    pub pcrs: Vec<(u8, [u8; PCR_BYTES])>,
    pub public_key: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

/// SHA-256, through the same ring the verifier pins, for callers that
/// fingerprint what a document carries (its public key, its bundle).
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, bytes);
    d.as_ref().try_into().expect("SHA-256 is 32 bytes")
}

impl Attested {
    pub fn pcr(&self, index: u8) -> Option<&[u8; PCR_BYTES]> {
        self.pcrs.iter().find(|(i, _)| *i == index).map(|(_, v)| v)
    }
}

/// Verifies a document whose nonce must be `expected`: the caller's own,
/// issued and kept by it.
pub fn verify(trust: &Trust, document: &[u8], expected: &[u8], now_ms: u64) -> Result<Attested, AttestError> {
    let attested = verify_signed_and_fresh(trust, document, now_ms)?;
    match attested.nonce.as_deref() {
        None => Err(AttestError::NonceMissing),
        Some(n) if n == expected => Ok(attested),
        Some(_) => Err(AttestError::NonceMismatch),
    }
}

/// Verifies a document whose nonce is one `nonces` issued: it must be
/// live and unused, and it is used up here. A replayed document, or one
/// answering a nonce from before a restart, is refused.
pub fn verify_issued(trust: &Trust, nonces: &mut Nonces, document: &[u8], now_ms: u64) -> Result<Attested, AttestError> {
    // The signature first: a forged document must not use up a nonce.
    let attested = verify_signed_and_fresh(trust, document, now_ms)?;
    let Some(n) = attested.nonce.as_deref() else {
        return Err(AttestError::NonceMissing);
    };
    nonces.redeem(n, now_ms)?;
    Ok(attested)
}

/// Every check but the nonce's.
fn verify_signed_and_fresh(trust: &Trust, document: &[u8], now_ms: u64) -> Result<Attested, AttestError> {
    let envelope = document::envelope(document)?;
    let payload = document::payload(envelope.payload)?;
    chain::verify(trust, &envelope, &payload, now_ms)?;
    let age_ms = now_ms.saturating_sub(payload.timestamp_ms);
    let ahead_ms = payload.timestamp_ms.saturating_sub(now_ms);
    if age_ms > AGE_MS_MAX {
        return Err(AttestError::Stale { age_ms, max_ms: AGE_MS_MAX });
    }
    if ahead_ms > SKEW_MS_MAX {
        return Err(AttestError::FromTheFuture { ahead_ms });
    }
    let attested = payload.into_attested();
    assert!(!attested.pcrs.is_empty() && attested.pcrs.len() as u64 <= PCRS_MAX);
    assert!(attested.pcrs.windows(2).all(|w| w[0].0 < w[1].0), "PCRs by ascending index, none twice");
    Ok(attested)
}
