//! The verifier end to end, on SELF-MADE documents (testkit.rs says why):
//! valid, invalid (a changed byte, a wrong root, expired and not-yet-valid
//! certificates, the key usage, a wrong signer, a wrong or missing nonce,
//! stale and future documents), replay, and restart.

use crate::testkit::{self, Chain, Fields, T0_MS};
use crate::{verify, verify_issued, webpki, AttestError, Nonces, Trust, AGE_MS_MAX, NONCE_BYTES, SKEW_MS_MAX};

const HOUR_S: i64 = 3600;

fn nonce_of(f: &Fields) -> Vec<u8> {
    f.nonce.clone().expect("the default fields carry a nonce")
}

// Goal: a document as the NSM makes it verifies, and every field comes
// back as it was signed. Method: the default fields, bare and tagged.
#[test]
fn a_valid_document_verifies() {
    let chain = Chain::new();
    for tagged in [false, true] {
        let mut f = Fields::new();
        f.tagged = tagged;
        let a = verify(&chain.trust(), &testkit::document(&chain, &f), &nonce_of(&f), T0_MS).expect("valid");
        assert_eq!(a.module_id, f.module_id);
        assert_eq!(a.timestamp_ms, T0_MS);
        assert_eq!(a.pcrs.len(), f.pcrs.len());
        assert_eq!(a.pcr(0), Some(&[1u8; 48]));
        assert_eq!(a.pcr(16), Some(&[0u8; 48]));
        assert_eq!(a.pcr(7), None);
        assert_eq!(a.public_key, f.public_key);
        assert_eq!(a.user_data, f.user_data);
        assert_eq!(a.nonce, f.nonce);
    }
}

// Goal: no single changed byte anywhere in a document gets through:
// the envelope's structure, the protected header, the payload (each
// certificate in it), and the signature. Method: flip the low bit of
// bytes spread evenly over the whole document, and the last.
#[test]
fn a_changed_byte_is_refused() {
    let chain = Chain::new();
    let f = Fields::new();
    let doc = testkit::document(&chain, &f);
    let trust = chain.trust();
    let nonce = nonce_of(&f);
    let step = (doc.len() / 150).max(1);
    let mut tried = 0;
    for i in (0..doc.len()).step_by(step).chain([doc.len() - 1]) {
        let mut changed = doc.clone();
        changed[i] ^= 0x01;
        let r = verify(&trust, &changed, &nonce, T0_MS);
        assert!(r.is_err(), "byte {i} of {} changed, and it verified", doc.len());
        tried += 1;
    }
    assert!(tried >= 150);
}

// Goal: a document cut short anywhere is refused before any crypto.
#[test]
fn a_cut_document_is_refused() {
    let chain = Chain::new();
    let f = Fields::new();
    let doc = testkit::document(&chain, &f);
    for cut in 0..doc.len() {
        assert!(verify(&chain.trust(), &doc[..cut], &nonce_of(&f), T0_MS).is_err(), "cut at {cut}");
    }
}

// Goal: only the pinned root is trusted. Method: another self-made
// root; AWS's real root; and a bundle that starts at the trusted root
// but whose intermediate another root signed.
#[test]
fn a_wrong_root_is_refused() {
    let ours = Chain::new();
    let theirs = Chain::new();
    let f = Fields::new();
    let doc = testkit::document(&ours, &f);
    assert_eq!(verify(&theirs.trust(), &doc, &nonce_of(&f), T0_MS), Err(AttestError::RootNotPinned));
    assert_eq!(verify(&Trust::aws_nitro_enclaves_root_g1(), &doc, &nonce_of(&f), T0_MS), Err(AttestError::RootNotPinned));
    let mut spliced = Fields::new();
    spliced.cabundle = Some(vec![theirs.root_der.clone(), ours.intermediate_der.clone()]);
    let doc = testkit::document(&ours, &spliced);
    // Both test roots bear one name, so webpki finds the trusted root as
    // the intermediate's issuer by name, then refuses its signature.
    match verify(&theirs.trust(), &doc, &nonce_of(&spliced), T0_MS) {
        Err(AttestError::Chain(webpki::Error::InvalidSignatureForPublicKey | webpki::Error::UnknownIssuer)) => {}
        other => panic!("a chain to another root: {other:?}"),
    }
}

// Goal: every certificate is held to its validity at the given time.
// Method: a signing certificate expired, one not yet valid, and a time
// past the root's own end (which webpki does not check for an anchor).
#[test]
fn certificates_outside_their_validity_are_refused() {
    let t0_s = (T0_MS / 1000) as i64;
    let f = Fields::new();
    let expired = Chain::with_leaf(t0_s - 4 * HOUR_S, t0_s - 1, true);
    match verify(&expired.trust(), &testkit::document(&expired, &f), &nonce_of(&f), T0_MS) {
        Err(AttestError::Chain(webpki::Error::CertExpired { .. })) => {}
        other => panic!("an expired signing certificate: {other:?}"),
    }
    let early = Chain::with_leaf(t0_s + HOUR_S, t0_s + 4 * HOUR_S, true);
    match verify(&early.trust(), &testkit::document(&early, &f), &nonce_of(&f), T0_MS) {
        Err(AttestError::Chain(webpki::Error::CertNotValidYet { .. })) => {}
        other => panic!("a signing certificate not yet valid: {other:?}"),
    }
    let chain = Chain::new();
    let late_ms = T0_MS + 31 * 365 * 24 * 3600 * 1000;
    let mut late = Fields::new();
    late.timestamp_ms = late_ms;
    assert_eq!(verify(&chain.trust(), &testkit::document(&chain, &late), &nonce_of(&late), late_ms), Err(AttestError::RootNotValidNow));
}

// Goal: the signing certificate must allow digitalSignature.
#[test]
fn a_signing_certificate_without_digital_signature_is_refused() {
    let t0_s = (T0_MS / 1000) as i64;
    let chain = Chain::with_leaf(t0_s - HOUR_S, t0_s + HOUR_S, false);
    let f = Fields::new();
    assert_eq!(verify(&chain.trust(), &testkit::document(&chain, &f), &nonce_of(&f), T0_MS), Err(AttestError::LeafKeyUsage));
}

// Goal: a valid chain is not enough; the document's own signature must
// be its signing certificate's. Method: a payload naming one chain's
// certificates, signed by another chain's key.
#[test]
fn a_signature_by_another_key_is_refused() {
    let named = Chain::new();
    let signer = Chain::new();
    let f = Fields::new();
    let doc = testkit::seal(&signer, &testkit::payload(&named, &f), false);
    assert_eq!(verify(&named.trust(), &doc, &nonce_of(&f), T0_MS), Err(AttestError::Signature));
}

// Goal: the nonce is the caller's, exactly.
#[test]
fn a_wrong_or_missing_nonce_is_refused() {
    let chain = Chain::new();
    let f = Fields::new();
    let doc = testkit::document(&chain, &f);
    assert_eq!(verify(&chain.trust(), &doc, &[0x5a; 32], T0_MS), Err(AttestError::NonceMismatch));
    assert_eq!(verify(&chain.trust(), &doc, &nonce_of(&f)[..31], T0_MS), Err(AttestError::NonceMismatch));
    let mut none = Fields::new();
    none.nonce = None;
    assert_eq!(verify(&chain.trust(), &testkit::document(&chain, &none), &nonce_of(&f), T0_MS), Err(AttestError::NonceMissing));
}

// Goal: the document's own time bounds its use. Method: at the age limit
// and one past it; at the skew limit and one past it.
#[test]
fn stale_and_future_documents_are_refused() {
    let chain = Chain::new();
    let f = Fields::new();
    let doc = testkit::document(&chain, &f);
    let n = nonce_of(&f);
    assert!(verify(&chain.trust(), &doc, &n, T0_MS + AGE_MS_MAX).is_ok());
    assert_eq!(verify(&chain.trust(), &doc, &n, T0_MS + AGE_MS_MAX + 1), Err(AttestError::Stale { age_ms: AGE_MS_MAX + 1, max_ms: AGE_MS_MAX }));
    assert!(verify(&chain.trust(), &doc, &n, T0_MS - SKEW_MS_MAX).is_ok());
    assert_eq!(verify(&chain.trust(), &doc, &n, T0_MS - SKEW_MS_MAX - 1), Err(AttestError::FromTheFuture { ahead_ms: SKEW_MS_MAX + 1 }));
}

/// A document answering `nonce`.
fn answering(chain: &Chain, nonce: [u8; NONCE_BYTES]) -> Vec<u8> {
    let mut f = Fields::new();
    f.nonce = Some(nonce.to_vec());
    testkit::document(chain, &f)
}

// Goal: a recorded document cannot be played back. Method: a nonce
// issued, its document verified, the same document again.
#[test]
fn a_replay_is_refused() {
    let chain = Chain::new();
    let mut nonces = Nonces::new();
    let n = nonces.issue([7; NONCE_BYTES], T0_MS).unwrap();
    let doc = answering(&chain, n.0);
    assert!(verify_issued(&chain.trust(), &mut nonces, &doc, T0_MS).is_ok());
    assert_eq!(verify_issued(&chain.trust(), &mut nonces, &doc, T0_MS), Err(AttestError::NonceUnknown));
    assert_eq!(nonces.outstanding(), 0);
}

// Goal: a forged document does not use up the nonce it names, so it
// cannot deny the real guest its answer. Method: a document with the
// right nonce and a wrong signature, then the real one.
#[test]
fn a_forgery_does_not_use_up_a_nonce() {
    let chain = Chain::new();
    let forger = Chain::new();
    let mut nonces = Nonces::new();
    let n = nonces.issue([9; NONCE_BYTES], T0_MS).unwrap();
    let mut f = Fields::new();
    f.nonce = Some(n.0.to_vec());
    let forged = testkit::seal(&forger, &testkit::payload(&chain, &f), false);
    assert_eq!(verify_issued(&chain.trust(), &mut nonces, &forged, T0_MS), Err(AttestError::Signature));
    assert_eq!(nonces.outstanding(), 1);
    assert!(verify_issued(&chain.trust(), &mut nonces, &answering(&chain, n.0), T0_MS).is_ok());
}

// Goal: after a restart the verifier knows no earlier nonce, so a
// document answering one is refused (it fails closed; the guest asks
// again). Method: a nonce issued by one ledger, presented to a new one
// (the restarted verifier), and still good on the first.
#[test]
fn a_nonce_from_before_a_restart_is_refused() {
    let chain = Chain::new();
    let mut before = Nonces::new();
    let n = before.issue([3; NONCE_BYTES], T0_MS).unwrap();
    let doc = answering(&chain, n.0);
    let mut after = Nonces::new();
    assert_eq!(verify_issued(&chain.trust(), &mut after, &doc, T0_MS), Err(AttestError::NonceUnknown));
    assert!(verify_issued(&chain.trust(), &mut before, &doc, T0_MS).is_ok(), "the document itself was valid");
}
