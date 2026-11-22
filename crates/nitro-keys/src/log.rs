//! A release Finite published in the public log, checked offline
//! (docs/nitro-keys.md, "The public log"). Pure.
//!
//! The log is Sigstore's Rekor, or one of its shape: an entry is a
//! `hashedrekord` (the SHA-256 of what was signed, the signature, the
//! signer's public key), and the log's promise to include it is its signed
//! entry timestamp (SET): the log's ECDSA P-256 signature over the
//! canonical JSON of the entry's body, time, log id and index. Both keys,
//! the log's and Finite's release key, are pinned in the key service's
//! measured image: the parent may hand over an entry, never decide one.
//!
//! What Finite signs, a release, is `{"finite-release":1,"image":"…","pcr0":"…"}`.

use base64::Engine as _;
use ring::digest;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use serde::{Deserialize, Serialize};

/// The DER prefix of a P-256 public key's SubjectPublicKeyInfo: what is left
/// is the uncompressed point.
const P256_SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
/// An entry's body, at most, decoded.
pub const BODY_BYTES_MAX: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    Malformed(&'static str),
    /// The log did not sign this entry (its SET), or it is another log's.
    NotLogged,
    /// The entry is not Finite's release key's, or its signature is not.
    NotFinites,
    /// A release, but of another image.
    OtherImage,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Malformed(why) => write!(f, "the log entry is malformed: {why}"),
            Refused::NotLogged => f.write_str("the log's signature on the entry does not verify under the pinned log key"),
            Refused::NotFinites => f.write_str("the entry is not a release signed by Finite's pinned release key"),
            Refused::OtherImage => f.write_str("the entry releases another image"),
        }
    }
}

impl std::error::Error for Refused {}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// A P-256 key, as the image pins it (its SubjectPublicKeyInfo, DER).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256Key {
    spki: Vec<u8>,
}

impl P256Key {
    pub fn from_spki(spki: &[u8]) -> Result<P256Key, Refused> {
        if spki.len() == P256_SPKI_PREFIX.len() + 65 && spki.starts_with(P256_SPKI_PREFIX) && spki[P256_SPKI_PREFIX.len()] == 4 {
            Ok(P256Key { spki: spki.to_vec() })
        } else {
            Err(Refused::Malformed("not a P-256 public key"))
        }
    }

    pub fn from_pem(pem: &str) -> Result<P256Key, Refused> {
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        P256Key::from_spki(&b64().decode(body.trim()).map_err(|_| Refused::Malformed("a PEM's base64"))?)
    }

    pub fn to_pem(&self) -> String {
        let encoded = b64().encode(&self.spki);
        let lines: Vec<&str> = encoded.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).expect("base64")).collect();
        format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", lines.join("\n"))
    }

    fn point(&self) -> &[u8] {
        &self.spki[P256_SPKI_PREFIX.len()..]
    }

    /// Rekor's id of a log: the SHA-256 of its key, hex.
    pub fn log_id(&self) -> String {
        hex::encode(digest::digest(&digest::SHA256, &self.spki))
    }

    fn verifies(&self, message: &[u8], der_signature: &[u8]) -> bool {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, self.point()).verify(message, der_signature).is_ok()
    }
}

/// An entry as the log serves it, with its SET.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The entry's body, base64, as the log keeps it.
    pub body: String,
    #[serde(rename = "integratedTime")]
    pub integrated_time: u64,
    #[serde(rename = "logID")]
    pub log_id: String,
    #[serde(rename = "logIndex")]
    pub log_index: u64,
    /// The log's signed entry timestamp, base64 DER.
    pub set: String,
    /// What Finite signed: the release, as its exact bytes, base64.
    pub release: String,
}

/// What the SET signs: the entry's canonical JSON (keys sorted, compact).
pub fn set_payload(body: &str, integrated_time: u64, log_id: &str, log_index: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "body": body, "integratedTime": integrated_time, "logID": log_id, "logIndex": log_index })).expect("JSON")
}

/// The release's exact bytes, for the image whose PCR0 is `pcr0`.
pub fn release_bytes(pcr0: &str, image: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "finite-release": 1, "image": image, "pcr0": pcr0 })).expect("JSON")
}

/// The body of a `hashedrekord` for `release`, signed `signature` by `key`.
pub fn hashedrekord(release: &[u8], signature: &[u8], key: &P256Key) -> String {
    let body = serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": { "hash": { "algorithm": "sha256", "value": hex::encode(digest::digest(&digest::SHA256, release)) } },
            "signature": { "content": b64().encode(signature), "publicKey": { "content": b64().encode(key.to_pem()) } },
        },
    });
    b64().encode(serde_json::to_vec(&body).expect("JSON"))
}

/// When the log took Finite's release of `pcr0`, once the log's SET, the
/// entry's signer and its signature, and the release itself all check.
pub fn published(entry: &Entry, pcr0: &str, log: &P256Key, finite: &P256Key) -> Result<u64, Refused> {
    if entry.log_id != log.log_id() {
        return Err(Refused::NotLogged);
    }
    let set = b64().decode(&entry.set).map_err(|_| Refused::Malformed("the SET's base64"))?;
    if !log.verifies(&set_payload(&entry.body, entry.integrated_time, &entry.log_id, entry.log_index), &set) {
        return Err(Refused::NotLogged);
    }
    let body = b64().decode(&entry.body).map_err(|_| Refused::Malformed("the body's base64"))?;
    if body.len() > BODY_BYTES_MAX {
        return Err(Refused::Malformed("the body's length"));
    }
    let body: serde_json::Value = serde_json::from_slice(&body).map_err(|_| Refused::Malformed("the body's JSON"))?;
    if body["kind"] != "hashedrekord" || body["spec"]["data"]["hash"]["algorithm"] != "sha256" {
        return Err(Refused::Malformed("not a sha256 hashedrekord"));
    }
    let pem = body["spec"]["signature"]["publicKey"]["content"].as_str().and_then(|p| b64().decode(p).ok()).and_then(|p| String::from_utf8(p).ok()).ok_or(Refused::Malformed("the signer's key"))?;
    if P256Key::from_pem(&pem)? != *finite {
        return Err(Refused::NotFinites);
    }
    let release = b64().decode(&entry.release).map_err(|_| Refused::Malformed("the release's base64"))?;
    if body["spec"]["data"]["hash"]["value"] != hex::encode(digest::digest(&digest::SHA256, &release)) {
        return Err(Refused::NotFinites);
    }
    let signature = body["spec"]["signature"]["content"].as_str().and_then(|s| b64().decode(s).ok()).ok_or(Refused::Malformed("the signature"))?;
    if !finite.verifies(&release, &signature) {
        return Err(Refused::NotFinites);
    }
    let release: serde_json::Value = serde_json::from_slice(&release).map_err(|_| Refused::Malformed("the release's JSON"))?;
    if release["finite-release"] != 1 || release["pcr0"] != pcr0 {
        return Err(Refused::OtherImage);
    }
    Ok(entry.integrated_time)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_ASN1_SIGNING};

    pub struct Signer(EcdsaKeyPair);

    impl Signer {
        pub fn new() -> Signer {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            Signer(EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap())
        }

        pub fn key(&self) -> P256Key {
            P256Key::from_spki(&[P256_SPKI_PREFIX, self.0.public_key().as_ref()].concat()).unwrap()
        }

        pub fn sign(&self, message: &[u8]) -> Vec<u8> {
            self.0.sign(&SystemRandom::new(), message).unwrap().as_ref().to_vec()
        }
    }

    /// A log's entry for Finite's release of `pcr0`, taken at `at`.
    pub fn entry(log: &Signer, finite: &Signer, pcr0: &str, at: u64) -> Entry {
        let release = release_bytes(pcr0, "home-test");
        let body = hashedrekord(&release, &finite.sign(&release), &finite.key());
        let log_id = log.key().log_id();
        let set = log.sign(&set_payload(&body, at, &log_id, 42));
        Entry { body, integrated_time: at, log_id, log_index: 42, set: b64().encode(set), release: b64().encode(release) }
    }

    fn pcr() -> String {
        "ab".repeat(48)
    }

    #[test]
    fn a_logged_release_reads_its_time() {
        let (log, finite) = (Signer::new(), Signer::new());
        assert_eq!(published(&entry(&log, &finite, &pcr(), 1_700), &pcr(), &log.key(), &finite.key()), Ok(1_700));
    }

    #[test]
    fn another_log_signer_or_image_is_refused() {
        let (log, finite, stranger) = (Signer::new(), Signer::new(), Signer::new());
        let good = entry(&log, &finite, &pcr(), 1_700);
        assert_eq!(published(&good, &pcr(), &stranger.key(), &finite.key()), Err(Refused::NotLogged), "another log");
        assert_eq!(published(&entry(&stranger, &finite, &pcr(), 1_700), &pcr(), &log.key(), &finite.key()), Err(Refused::NotLogged));
        assert_eq!(published(&entry(&log, &stranger, &pcr(), 1_700), &pcr(), &log.key(), &finite.key()), Err(Refused::NotFinites), "not Finite's key");
        assert_eq!(published(&good, &"cd".repeat(48), &log.key(), &finite.key()), Err(Refused::OtherImage));
        let mut earlier = good.clone();
        earlier.integrated_time = 1;
        assert_eq!(published(&earlier, &pcr(), &log.key(), &finite.key()), Err(Refused::NotLogged), "a time the log did not sign");
        let mut swapped = good.clone();
        swapped.release = b64().encode(release_bytes(&pcr(), "another"));
        assert_eq!(published(&swapped, &pcr(), &log.key(), &finite.key()), Err(Refused::NotFinites), "a release the entry does not hash");
    }

    #[test]
    fn a_key_round_trips_its_pem() {
        let key = Signer::new().key();
        assert_eq!(P256Key::from_pem(&key.to_pem()), Ok(key));
        assert!(P256Key::from_spki(&[0u8; 91]).is_err());
    }
}
