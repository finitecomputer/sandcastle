//! What the key service answers (docs/nitro-keys.md). Pure but for its
//! clock and randomness, which the caller passes: one ask in, one answer
//! out, and whether the state changed (so the caller seals and keeps it).
//!
//! Nothing here needs a protected channel. A statement is signed by its
//! owner; a release is sealed to the public key in the asking home's own
//! attestation document, which only that home's image, running, holds the
//! private half of. The parent relays the bytes and learns nothing it could
//! use.

use base64::Engine as _;
use rsa::pkcs8::DecodePublicKey as _;
use rsa::{Oaep, RsaPublicKey};
use sandcastle_nitro_attest::{verify_issued, Nonces, Trust};
use serde::{Deserialize, Serialize};

use crate::log::{self, P256Key};
use crate::rule::Decision;
use crate::state::State;

/// An ask, at most, as JSON.
pub const ASK_BYTES_MAX: usize = 64 * 1024;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "ask", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Ask {
    /// A nonce for the next release's attestation document.
    Nonce,
    /// An owner's statement: the event as signed.
    Statement { event: String },
    /// The home's key, for the image this document attests, with the log's
    /// entry for that image when the owner's rule needs one.
    Release {
        home: String,
        document: String,
        #[serde(default)]
        entry: Option<log::Entry>,
    },
    /// Until when this person may repair the home.
    Repair { home: String, person: String },
    /// The service's own attestation document, carrying its RSA key: what
    /// the operator checks before sealing a new home's key to it.
    Attest { nonce: String },
    /// A new home, its owner (a nostr key, hex) and its key, sealed to the
    /// key in the service's own document. Made when the home is made.
    AddHome { home: String, owner: String, key: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "answer", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Answer {
    Nonce { nonce: String },
    Taken { generation: u64 },
    /// The home's key, RSA-OAEP (SHA-256) to the document's public key.
    Released { key: String, why: String },
    Refused { why: String },
    Repair { until: Option<u64> },
    Attested { document: String },
    Added { generation: u64 },
}

pub fn refused(why: impl std::fmt::Display) -> Answer {
    Answer::Refused { why: why.to_string() }
}

pub struct Service {
    pub state: State,
    trust: Trust,
    nonces: Nonces,
    /// The public log's key and Finite's release key, as the image pins them.
    log: P256Key,
    finite: P256Key,
}

impl Service {
    pub fn new(state: State, trust: Trust, log: P256Key, finite: P256Key) -> Service {
        Service { state, trust, nonces: Nonces::new(), log, finite }
    }

    /// One answer to one ask at `now_ms`, and whether the state changed.
    /// `random` is 32 bytes for a nonce.
    pub fn answer(&mut self, ask: Ask, now_ms: u64, random: [u8; 32], rng: &mut impl rsa::rand_core::CryptoRngCore) -> (Answer, bool) {
        let now = now_ms / 1000;
        match ask {
            Ask::Nonce => match self.nonces.issue(random, now_ms) {
                Ok(nonce) => (Answer::Nonce { nonce: hex::encode(nonce.0) }, false),
                Err(why) => (refused(format!("no nonce now: {why:?}")), false),
            },
            Ask::Statement { event } => match self.state.take(&event, now) {
                Ok(()) => (Answer::Taken { generation: self.state.generation }, true),
                Err(why) => (refused(why), false),
            },
            Ask::Release { home, document, entry } => (self.release(&home, &document, entry.as_ref(), now_ms, rng), false),
            // the service's own key answers these (bin/nitro-keys.rs)
            Ask::Attest { .. } | Ask::AddHome { .. } => (refused("only the service's own key answers this"), false),
            Ask::Repair { home, person } => {
                let Some(record) = self.state.home(&home) else { return (refused("no such home"), false) };
                let Some(person) = hex::decode(&person).ok().and_then(|p| <[u8; 32]>::try_from(p).ok()) else {
                    return (refused("a person is a 32-byte key, hex"), false);
                };
                (Answer::Repair { until: record.home.repair_until(&person, now) }, false)
            }
        }
    }

    fn release(&mut self, home: &str, document: &str, entry: Option<&log::Entry>, now_ms: u64, rng: &mut impl rsa::rand_core::CryptoRngCore) -> Answer {
        let Some(record) = self.state.home(home) else { return refused("no such home") };
        let Ok(document) = base64::engine::general_purpose::STANDARD.decode(document) else { return refused("the document is not base64") };
        let attested = match verify_issued(&self.trust, &mut self.nonces, &document, now_ms) {
            Ok(attested) => attested,
            Err(why) => return refused(format!("the document: {why}")),
        };
        let Some((_, pcr0)) = attested.pcrs.iter().find(|(index, _)| *index == 0) else { return refused("the document has no PCR0") };
        let pcr0 = hex::encode(pcr0);
        let published = match entry.map(|e| log::published(e, &pcr0, &self.log, &self.finite)).transpose() {
            Ok(at) => at,
            Err(why) => return refused(format!("the log entry: {why}")),
        };
        let why = match record.home.may_release(&pcr0, published, now_ms / 1000) {
            Decision::Named => "the owner named this image".to_string(),
            Decision::Published { at } => format!("the owner's rule: Finite published this image at {at}"),
            Decision::NotYet { from } => return refused(format!("the owner's rule takes this image from {from}, not yet")),
            Decision::No => return refused(format!("nothing the owner signed covers the image {pcr0}")),
        };
        let Some(public) = attested.public_key.as_deref().and_then(|k| RsaPublicKey::from_public_key_der(k).ok()) else {
            return refused("the document carries no RSA public key to seal the key to");
        };
        match public.encrypt(rng, Oaep::new::<sha2::Sha256>(), &record.key) {
            Ok(sealed) => Answer::Released { key: base64::engine::general_purpose::STANDARD.encode(sealed), why },
            Err(why) => refused(format!("sealing the key: {why}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::tests::{entry, Signer};
    use crate::statement::{sign, tests::key, Says};
    use rsa::pkcs8::EncodePublicKey as _;
    use rsa::RsaPrivateKey;
    use sandcastle_nitro_attest::testkit::{document, Chain, Fields, T0_MS};

    const HOME_KEY: [u8; 32] = [7; 32];

    struct World {
        chain: Chain,
        log: Signer,
        finite: Signer,
        service: Service,
        rng: rsa::rand_core::OsRng,
    }

    fn pcr(byte: u8) -> Vec<u8> {
        vec![byte; 48]
    }

    impl World {
        fn new() -> World {
            let (chain, log, finite) = (Chain::new(), Signer::new(), Signer::new());
            let mut state = State::default();
            state.add_home("h", key(1).verifying_key().to_bytes().into(), HOME_KEY).unwrap();
            let service = Service::new(state, chain.trust(), log.key(), finite.key());
            World { chain, log, finite, service, rng: rsa::rand_core::OsRng }
        }

        fn ask(&mut self, ask: Ask, now_ms: u64) -> Answer {
            let mut random = [0u8; 32];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random).unwrap();
            self.service.answer(ask, now_ms, random, &mut self.rng).0
        }

        fn say(&mut self, says: &Says, at_s: u64) -> Answer {
            let event = sign(&key(1), "h", says, at_s, [0; 32]);
            self.ask(Ask::Statement { event: serde_json::to_string(&event).unwrap() }, at_s * 1000)
        }

        /// A home of the image `pcr0` asking for its key at `now_ms`: its
        /// document, made with a fresh nonce and its own RSA key.
        fn release(&mut self, pcr0: &[u8], log_entry: Option<log::Entry>, now_ms: u64) -> (Answer, RsaPrivateKey) {
            let Answer::Nonce { nonce } = self.ask(Ask::Nonce, now_ms) else { panic!("a nonce") };
            let private = RsaPrivateKey::new(&mut self.rng, 1024).unwrap();
            let mut fields = Fields::new();
            fields.timestamp_ms = now_ms;
            fields.pcrs = vec![(0, pcr0.to_vec()), (1, pcr(9)), (2, pcr(9))];
            fields.public_key = Some(private.to_public_key().to_public_key_der().unwrap().as_bytes().to_vec());
            fields.nonce = Some(hex::decode(nonce).unwrap());
            let document = base64::engine::general_purpose::STANDARD.encode(document(&self.chain, &fields));
            (self.ask(Ask::Release { home: "h".into(), document, entry: log_entry }, now_ms), private)
        }
    }

    fn opened(answer: &Answer, private: &RsaPrivateKey) -> [u8; 32] {
        let Answer::Released { key, .. } = answer else { panic!("released: {answer:?}") };
        let sealed = base64::engine::general_purpose::STANDARD.decode(key).unwrap();
        private.decrypt(Oaep::new::<sha2::Sha256>(), &sealed).unwrap().try_into().unwrap()
    }

    fn refused(answer: &Answer) -> &str {
        match answer {
            Answer::Refused { why } => why,
            other => panic!("refused: {other:?}"),
        }
    }

    #[test]
    fn nothing_signed_releases_nothing() {
        let mut w = World::new();
        let (answer, _) = w.release(&pcr(1), None, T0_MS);
        assert!(refused(&answer).contains("nothing the owner signed"), "{answer:?}");
    }

    #[test]
    fn the_image_the_owner_named_gets_the_key_sealed_to_it_alone() {
        let mut w = World::new();
        assert!(matches!(w.say(&Says::Release { pcr0: hex::encode(pcr(1)) }, T0_MS / 1000), Answer::Taken { .. }));
        let (answer, private) = w.release(&pcr(1), None, T0_MS);
        assert_eq!(opened(&answer, &private), HOME_KEY);
        let (other, _) = w.release(&pcr(2), None, T0_MS);
        assert!(refused(&other).contains("nothing the owner signed"), "another image");
    }

    #[test]
    fn the_default_rule_waits_a_day_after_finites_logged_release() {
        let mut w = World::new();
        let now_s = T0_MS / 1000;
        w.say(&Says::AcceptPublishedReleases { after_s: 86_400 }, now_s);
        let pcr0 = hex::encode(pcr(3));
        let young = entry(&w.log, &w.finite, &pcr0, now_s - 3_600);
        let (answer, _) = w.release(&pcr(3), Some(young), T0_MS);
        assert!(refused(&answer).contains("not yet"), "{answer:?}");
        let (answer, _) = w.release(&pcr(3), None, T0_MS);
        assert!(refused(&answer).contains("nothing the owner signed"), "no entry, no publication");
        let old = entry(&w.log, &w.finite, &pcr0, now_s - 86_400);
        let (answer, private) = w.release(&pcr(3), Some(old.clone()), T0_MS);
        assert_eq!(opened(&answer, &private), HOME_KEY);
        let (answer, _) = w.release(&pcr(4), Some(old), T0_MS);
        assert!(refused(&answer).contains("another image"), "an entry for another image: {answer:?}");
        let forged = entry(&Signer::new(), &w.finite, &pcr0, now_s - 86_400);
        let (answer, _) = w.release(&pcr(3), Some(forged), T0_MS);
        assert!(refused(&answer).contains("log"), "another log's entry: {answer:?}");
    }

    #[test]
    fn a_document_is_used_once_and_only_with_a_nonce_the_service_gave() {
        let mut w = World::new();
        w.say(&Says::Release { pcr0: hex::encode(pcr(1)) }, T0_MS / 1000);
        let private = RsaPrivateKey::new(&mut w.rng, 1024).unwrap();
        let made = |w: &World, nonce: Vec<u8>| {
            let mut fields = Fields::new();
            fields.pcrs = vec![(0, pcr(1))];
            fields.public_key = Some(private.to_public_key().to_public_key_der().unwrap().as_bytes().to_vec());
            fields.nonce = Some(nonce);
            base64::engine::general_purpose::STANDARD.encode(document(&w.chain, &fields))
        };
        let stranger = made(&w, vec![0x42; 32]);
        let answer = w.ask(Ask::Release { home: "h".into(), document: stranger, entry: None }, T0_MS);
        assert!(refused(&answer).contains("the document"), "a nonce it never gave: {answer:?}");
        let Answer::Nonce { nonce } = w.ask(Ask::Nonce, T0_MS) else { panic!("a nonce") };
        let document = made(&w, hex::decode(nonce).unwrap());
        let first = w.ask(Ask::Release { home: "h".into(), document: document.clone(), entry: None }, T0_MS);
        assert_eq!(opened(&first, &private), HOME_KEY);
        let again = w.ask(Ask::Release { home: "h".into(), document, entry: None }, T0_MS);
        assert!(refused(&again).contains("the document"), "the same document again: {again:?}");
    }

    #[test]
    fn only_the_owners_statements_count() {
        let mut w = World::new();
        let event = sign(&key(2), "h", &Says::Release { pcr0: hex::encode(pcr(1)) }, T0_MS / 1000, [0; 32]);
        let answer = w.ask(Ask::Statement { event: serde_json::to_string(&event).unwrap() }, T0_MS);
        assert!(refused(&answer).contains("owner"), "{answer:?}");
        let (answer, _) = w.release(&pcr(1), None, T0_MS);
        assert!(matches!(answer, Answer::Refused { .. }));
    }

    #[test]
    fn a_repair_grant_answers_until_it_ends() {
        let mut w = World::new();
        let person = hex::encode([5u8; 32]);
        w.say(&Says::Repair { to: person.clone(), until: T0_MS / 1000 + 600 }, T0_MS / 1000);
        assert_eq!(w.ask(Ask::Repair { home: "h".into(), person: person.clone() }, T0_MS), Answer::Repair { until: Some(T0_MS / 1000 + 600) });
        assert_eq!(w.ask(Ask::Repair { home: "h".into(), person }, T0_MS + 601_000), Answer::Repair { until: None });
    }
}
