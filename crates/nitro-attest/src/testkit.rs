//! Test fixtures: a SELF-MADE chain and documents signed by it, in the
//! NSM's encoding. AWS publishes no sample attestation document or test
//! vector (searched 2026-11-20: aws-nitro-enclaves-nsm-api, -cose,
//! -sdk-c, -samples, -image-format), so the valid and invalid cases here
//! are built, not recorded. The chain has AWS's shape (a root, an
//! intermediate, a signing certificate valid for hours, all P-384 with
//! SHA-384) under a test root that no real verifier trusts. A real
//! document is verified against AWS's root on the instance's run
//! (docs/nitro-spike.md, acceptance 4).

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P384_SHA384};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_FIXED_SIGNING};

use crate::cbor::write_head;
use crate::document::sig_structure;
use crate::Trust;

/// The fixtures' "now": 2027-01-15T08:00:00Z, in milliseconds.
pub const T0_MS: u64 = 1_800_000_000_000;
pub const T0_S: i64 = (T0_MS / 1000) as i64;
const HOUR_S: i64 = 3600;
const DAY_S: i64 = 24 * HOUR_S;

/// `{1: -35}`: ES384.
pub const PROTECTED_ES384: &[u8] = &[0xa1, 0x01, 0x38, 0x22];

pub struct Chain {
    pub root_der: Vec<u8>,
    pub intermediate_der: Vec<u8>,
    pub leaf_der: Vec<u8>,
    leaf_pkcs8: Vec<u8>,
}

fn at(s: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(s).expect("a test time")
}

fn ca(name: &str, path_len: u8, from_s: i64, to_s: i64) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
    p.distinguished_name.push(DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    p.not_before = at(from_s);
    p.not_after = at(to_s);
    p
}

impl Chain {
    /// The usual chain: the leaf valid for three hours around T0, as AWS's
    /// signing certificates are.
    pub fn new() -> Chain {
        Chain::with_leaf(T0_S - HOUR_S, T0_S + 3 * HOUR_S, true)
    }

    pub fn with_leaf(leaf_from_s: i64, leaf_to_s: i64, digital_signature: bool) -> Chain {
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("a P-384 key");
        let root_params = ca("SELF-MADE test root, not AWS", 2, T0_S - 365 * DAY_S, T0_S + 30 * 365 * DAY_S);
        let root = root_params.self_signed(&root_key).expect("the root");
        let root_issuer = Issuer::new(root_params, root_key);
        let mid_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("a P-384 key");
        let mid_params = ca("SELF-MADE test intermediate", 0, T0_S - 30 * DAY_S, T0_S + 365 * DAY_S);
        let mid = mid_params.signed_by(&mid_key, &root_issuer).expect("the intermediate");
        let mid_issuer = Issuer::new(mid_params, mid_key);
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("a P-384 key");
        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("params");
        leaf_params.distinguished_name.push(DnType::CommonName, "SELF-MADE test signing certificate");
        leaf_params.is_ca = IsCa::ExplicitNoCa;
        leaf_params.key_usages = if digital_signature { vec![KeyUsagePurpose::DigitalSignature] } else { vec![KeyUsagePurpose::KeyAgreement] };
        leaf_params.not_before = at(leaf_from_s);
        leaf_params.not_after = at(leaf_to_s);
        let leaf = leaf_params.signed_by(&leaf_key, &mid_issuer).expect("the leaf");
        Chain { root_der: root.der().to_vec(), intermediate_der: mid.der().to_vec(), leaf_der: leaf.der().to_vec(), leaf_pkcs8: leaf_key.serialize_der() }
    }

    pub fn trust(&self) -> Trust {
        Trust::from_root_der(&self.root_der).expect("the test root")
    }

    /// ES384 over `message` with the leaf's key, r and s side by side.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &self.leaf_pkcs8, &rng).expect("the leaf's key");
        key.sign(&rng, message).expect("a signature").as_ref().to_vec()
    }
}

/// A document's fields, valid by default, each changeable by a test.
pub struct Fields {
    pub module_id: String,
    pub digest: String,
    pub timestamp_ms: u64,
    pub pcrs: Vec<(u64, Vec<u8>)>,
    pub public_key: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
    /// Keys left out of the map.
    pub omit: Vec<&'static str>,
    /// Keys written again, or unknown keys, after the rest.
    pub append: Vec<&'static str>,
    /// The bundle written as given, in place of the chain's root and
    /// intermediate.
    pub cabundle: Option<Vec<Vec<u8>>>,
    /// CBOR tag 18 before the envelope.
    pub tagged: bool,
    /// The payload's map of indefinite length, closed by a break, as the
    /// real NSM writes it (the NSM API's serde writes a definite one).
    pub indefinite: bool,
}

impl Fields {
    pub fn new() -> Fields {
        Fields {
            module_id: "i-00000000000000000-enc0000000000000000".into(),
            digest: "SHA384".into(),
            timestamp_ms: T0_MS,
            pcrs: (0..5u64).map(|i| (i, vec![i as u8 + 1; 48])).chain([(16, vec![0; 48])]).collect(),
            public_key: Some(vec![0x30; 294]),
            user_data: Some(b"user data".to_vec()),
            nonce: Some(vec![0xa5; 32]),
            omit: vec![],
            append: vec![],
            cabundle: None,
            tagged: false,
            indefinite: true,
        }
    }
}

fn text(out: &mut Vec<u8>, s: &str) {
    write_head(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn bytes(out: &mut Vec<u8>, b: &[u8]) {
    write_head(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

fn optional(out: &mut Vec<u8>, b: &Option<Vec<u8>>) {
    match b {
        Some(b) => bytes(out, b),
        None => out.push(0xf6),
    }
}

fn value(out: &mut Vec<u8>, key: &str, chain: &Chain, f: &Fields) {
    match key {
        "module_id" => text(out, &f.module_id),
        "digest" => text(out, &f.digest),
        "timestamp" => write_head(out, 0, f.timestamp_ms),
        "pcrs" => {
            write_head(out, 5, f.pcrs.len() as u64);
            for (i, v) in &f.pcrs {
                write_head(out, 0, *i);
                bytes(out, v);
            }
        }
        "certificate" => bytes(out, &chain.leaf_der),
        "cabundle" => {
            let bundle = f.cabundle.clone().unwrap_or_else(|| vec![chain.root_der.clone(), chain.intermediate_der.clone()]);
            write_head(out, 4, bundle.len() as u64);
            for c in &bundle {
                bytes(out, c);
            }
        }
        "public_key" => optional(out, &f.public_key),
        "user_data" => optional(out, &f.user_data),
        "nonce" => optional(out, &f.nonce),
        _ => out.push(0xf6),
    }
}

/// The payload as the NSM writes it: a map in its field order.
pub fn payload(chain: &Chain, f: &Fields) -> Vec<u8> {
    const ORDER: [&str; 9] = ["module_id", "digest", "timestamp", "pcrs", "certificate", "cabundle", "public_key", "user_data", "nonce"];
    let keys: Vec<&str> = ORDER.iter().copied().filter(|k| !f.omit.contains(k)).chain(f.append.iter().copied()).collect();
    let mut out = Vec::new();
    if f.indefinite {
        out.push(0xbf);
    } else {
        write_head(&mut out, 5, keys.len() as u64);
    }
    for k in keys {
        text(&mut out, k);
        value(&mut out, k, chain, f);
    }
    if f.indefinite {
        out.push(0xff);
    }
    out
}

/// A COSE_Sign1 around `payload`, signed by `signer`'s leaf.
pub fn seal(signer: &Chain, payload: &[u8], tagged: bool) -> Vec<u8> {
    let signature = signer.sign(&sig_structure(PROTECTED_ES384, payload));
    let mut out = Vec::new();
    if tagged {
        write_head(&mut out, 6, 18);
    }
    write_head(&mut out, 4, 4);
    bytes(&mut out, PROTECTED_ES384);
    write_head(&mut out, 5, 0);
    bytes(&mut out, payload);
    bytes(&mut out, &signature);
    out
}

pub fn document(chain: &Chain, f: &Fields) -> Vec<u8> {
    seal(chain, &payload(chain, f), f.tagged)
}
