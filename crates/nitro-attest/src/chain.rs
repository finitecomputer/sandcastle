//! The trust: the pinned root, the chain from it to the certificate that
//! signed the document, and the signature itself (attestation_process.md,
//! 3.2.3 and 3.2.4; AWS's "Verifying the root of trust").

use std::time::Duration;

use rustls_pki_types::{CertificateDer, UnixTime};
use webpki::{EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter};

use crate::der::{self, Validity};
use crate::document::{self, Envelope, Payload};
use crate::{AttestError, SIGNATURE_BYTES};

/// The AWS Nitro Enclaves root certificate, G1, as DER: the only file in
/// `https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip`
/// (`root.pem`), downloaded 2026-11-20. Nitro Sandboxes' documents chain
/// to the same root (the EC2 User Guide, "Nitro Sandboxes attestation").
const AWS_ROOT_G1: &[u8] = include_bytes!("aws-nitro-enclaves-root-g1.der");

/// SHA-256 of [`AWS_ROOT_G1`], pinned from AWS's own documentation: the
/// Nitro Enclaves User Guide, "Verifying the root of trust"
/// (docs.aws.amazon.com/enclaves/latest/user/verify-root.html, read
/// 2026-11-20), which gives the root's fingerprint as
/// `64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`.
/// (The zip itself hashes to `8cf60e2b…faff7c`, as the NSM API's
/// `docs/attestation_process.md` says; checked on download.)
pub const AWS_ROOT_G1_SHA256: [u8; 32] = [
    0x64, 0x1a, 0x03, 0x21, 0xa3, 0xe2, 0x44, 0xef, 0xe4, 0x56, 0x46, 0x31, 0x95, 0xd6, 0x06, 0x31, 0x7e, 0xd7, 0xcd, 0xcc, 0x3c, 0x17, 0x56, 0xe0, 0x98, 0x93, 0xf3, 0xc6, 0x8f, 0x79, 0xbb, 0x5b,
];

/// One trusted root: its DER, and its validity, read once.
#[derive(Debug, Clone)]
pub struct Trust {
    root: Vec<u8>,
    validity: Validity,
}

impl Trust {
    /// AWS's root. The embedded bytes are asserted against the pinned
    /// fingerprint: a changed file is a programmer's error, not an input.
    pub fn aws_nitro_enclaves_root_g1() -> Trust {
        let sum = ring::digest::digest(&ring::digest::SHA256, AWS_ROOT_G1);
        assert_eq!(sum.as_ref(), &AWS_ROOT_G1_SHA256[..], "the embedded root is the one AWS's guide fingerprints");
        let trust = Trust::from_root_der(AWS_ROOT_G1).expect("AWS's root parses");
        assert!(trust.validity.not_before_s < trust.validity.not_after_s);
        trust
    }

    /// Another root: a test's own, or a later AWS root once pinned.
    pub fn from_root_der(der: &[u8]) -> Result<Trust, AttestError> {
        let validity = der::validity(der).map_err(AttestError::Der)?;
        let cert = CertificateDer::from(der);
        webpki::anchor_from_trusted_cert(&cert).map_err(AttestError::Chain)?;
        Ok(Trust { root: der.to_vec(), validity })
    }

    pub fn root_sha256(&self) -> [u8; 32] {
        let sum = ring::digest::digest(&ring::digest::SHA256, &self.root);
        sum.as_ref().try_into().expect("SHA-256 is 32 bytes")
    }

    /// The root's validity: seconds since the Unix epoch, both ends kept.
    pub fn root_validity_s(&self) -> (i64, i64) {
        (self.validity.not_before_s, self.validity.not_after_s)
    }
}

/// Any extended key usage, or none: AWS's process names no purpose for
/// the signing certificate, only its key usage (checked separately). The
/// list is still read to its end, so a malformed one is refused.
struct AnyPurpose;

impl ExtendedKeyUsageValidator for AnyPurpose {
    fn validate(&self, iter: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        for purpose in iter {
            purpose?;
        }
        Ok(())
    }
}

/// The chain, then the signature.
pub(crate) fn verify(trust: &Trust, envelope: &Envelope<'_>, payload: &Payload<'_>, now_ms: u64) -> Result<(), AttestError> {
    assert_eq!(envelope.signature.len(), SIGNATURE_BYTES, "checked by the envelope");
    // The bundle starts at the root (attestation_process.md, 3.2.4): ours,
    // byte for byte, or nothing below it is trusted.
    let (first, intermediates) = payload.cabundle.split_first().expect("at least one, checked by the payload");
    if *first != trust.root.as_slice() {
        return Err(AttestError::RootNotPinned);
    }
    let now_s = i64::try_from(now_ms / 1000).unwrap_or(i64::MAX);
    if !trust.validity.holds_at(now_s) {
        return Err(AttestError::RootNotValidNow);
    }
    let root = CertificateDer::from(trust.root.as_slice());
    let anchor = webpki::anchor_from_trusted_cert(&root).map_err(AttestError::Chain)?;
    let intermediates: Vec<CertificateDer<'_>> = intermediates.iter().map(|c| CertificateDer::from(*c)).collect();
    let leaf_der = CertificateDer::from(payload.certificate);
    let leaf = EndEntityCert::try_from(&leaf_der).map_err(AttestError::Chain)?;
    let time = UnixTime::since_unix_epoch(Duration::from_millis(now_ms));
    leaf.verify_for_usage(&[webpki::ring::ECDSA_P384_SHA384], &[anchor], &intermediates, time, AnyPurpose, None, None).map_err(AttestError::Chain)?;
    if !der::allows_digital_signature(payload.certificate).map_err(AttestError::Der)? {
        return Err(AttestError::LeafKeyUsage);
    }
    let message = document::sig_structure(envelope.protected, envelope.payload);
    let signature = ecdsa_der(envelope.signature);
    leaf.verify_signature(webpki::ring::ECDSA_P384_SHA384, &message, &signature).map_err(|_| AttestError::Signature)
}

/// COSE signs with r and s side by side (RFC 9053, 2.1); webpki takes
/// X.509's `ECDSA-Sig-Value`, a DER SEQUENCE of two INTEGERs.
fn ecdsa_der(fixed: &[u8]) -> Vec<u8> {
    assert_eq!(fixed.len(), SIGNATURE_BYTES);
    let (r, s) = fixed.split_at(SIGNATURE_BYTES / 2);
    let mut body = Vec::with_capacity(SIGNATURE_BYTES + 6);
    der_unsigned(&mut body, r);
    der_unsigned(&mut body, s);
    // Two INTEGERs of at most 49 bytes each: always a short-form length.
    assert!(body.len() < 0x80);
    let mut out = Vec::with_capacity(body.len() + 2);
    out.extend_from_slice(&[0x30, body.len() as u8]);
    out.extend_from_slice(&body);
    out
}

/// A big-endian unsigned integer as DER: no leading zeros but one, and a
/// zero added when the high bit is set, so it reads as positive.
fn der_unsigned(out: &mut Vec<u8>, be: &[u8]) {
    let first = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
    let digits = &be[first..];
    let pad = digits[0] & 0x80 != 0;
    out.push(0x02);
    out.push((digits.len() + usize::from(pad)) as u8);
    if pad {
        out.push(0);
    }
    out.extend_from_slice(digits);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: the embedded root is AWS's, and its dates are what openssl
    // reads from it (notBefore 2019-10-28 13:28:05, notAfter 2049-10-28
    // 14:28:05, UTC). Method: the pinned constructor, its fingerprint and
    // the DER walk's dates.
    #[test]
    fn the_aws_root_is_pinned() {
        let t = Trust::aws_nitro_enclaves_root_g1();
        assert_eq!(t.root_sha256(), AWS_ROOT_G1_SHA256);
        assert_eq!(t.root_validity_s(), (1_572_269_285, 2_519_044_085));
    }

    // Goal: r and s become DER integers whatever their leading bytes.
    // Method: a high bit (padded), leading zeros (stripped), all zero.
    #[test]
    fn fixed_signatures_become_der() {
        let mut sig = [0u8; 96];
        sig[0] = 0x80;
        sig[95] = 0x01;
        let der = ecdsa_der(&sig);
        assert_eq!(&der[..5], &[0x30, 2 + 49 + 2 + 1, 0x02, 49, 0x00]);
        assert_eq!(&der[der.len() - 3..], &[0x02, 0x01, 0x01]);
        let zero = ecdsa_der(&[0u8; 96]);
        assert_eq!(zero, vec![0x30, 6, 0x02, 1, 0, 0x02, 1, 0]);
    }
}
