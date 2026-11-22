//! The key service's state, sealed (docs/nitro-keys.md, "Its own state"):
//! each home, its owner, its statements and its wrapping key. Pure.
//!
//! The state's key comes from shares. Today there is one, released by KMS
//! only to the key service's PCR0, so whoever can rewrite that KMS key's
//! policy (the AWS project's administrators, and AWS) holds the rule too.
//! A second share, from a lock KMS never sees, slots in beside it: a state
//! sealed with two shares does not open with one.

use std::collections::BTreeMap;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::hkdf;
use serde::{Deserialize, Serialize};

use crate::rule::Home;
use crate::statement;

/// The state sealed, at most.
pub const SEALED_BYTES_MAX: usize = 4 << 20;
/// Homes one key service holds, at most.
pub const HOMES_MAX: usize = 1024;
const MAGIC: &[u8; 8] = b"nkstate1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// Not this service's state under these shares: another key, or changed.
    DoesNotOpen,
    Malformed(&'static str),
    /// A state older than the one this service holds.
    Older { found: u64, held: u64 },
    Full,
    Exists,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::DoesNotOpen => f.write_str("the state does not open under this service's shares"),
            Refused::Malformed(why) => write!(f, "the state is malformed: {why}"),
            Refused::Older { found, held } => write!(f, "the state is generation {found}, older than {held}"),
            Refused::Full => write!(f, "the service holds its most homes ({HOMES_MAX})"),
            Refused::Exists => f.write_str("the home exists"),
        }
    }
}

impl std::error::Error for Refused {}

/// The shares the state's key is made of.
pub struct Shares {
    pub kms: [u8; 32],
    /// The second lock, when there is one. None today.
    pub second: Option<[u8; 32]>,
}

struct Len;

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        32
    }
}

impl Shares {
    fn key(&self) -> LessSafeKey {
        let (ikm, info): (Vec<u8>, &[u8]) = match &self.second {
            Some(second) => ([self.kms, *second].concat(), b"two shares"),
            None => (self.kms.to_vec(), b"one share"),
        };
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"nitro-keys state v1").extract(&ikm);
        let mut key = [0u8; 32];
        prk.expand(&[info], Len).expect("32 bytes").fill(&mut key).expect("32 bytes");
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).expect("a 32-byte key"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeRecord {
    pub home: Home,
    /// The key the home's own keys are wrapped with.
    pub key: [u8; 32],
    /// The events its statements came as, kept as they were signed.
    events: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct State {
    /// Raised at every write: a state older than the one held is refused.
    pub generation: u64,
    homes: BTreeMap<String, HomeRecord>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    generation: u64,
    homes: Vec<StoredHome>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredHome {
    name: String,
    owner: String,
    key: String,
    events: Vec<String>,
}

impl State {
    pub fn home(&self, name: &str) -> Option<&HomeRecord> {
        self.homes.get(name)
    }

    /// A new home, its owner and its key: made when the home is.
    pub fn add_home(&mut self, name: &str, owner: [u8; 32], key: [u8; 32]) -> Result<(), Refused> {
        if self.homes.contains_key(name) {
            return Err(Refused::Exists);
        }
        if self.homes.len() >= HOMES_MAX {
            return Err(Refused::Full);
        }
        self.homes.insert(name.to_string(), HomeRecord { home: Home::new(name, owner), key, events: Vec::new() });
        self.generation += 1;
        Ok(())
    }

    /// The owner's statement, as signed, taken into its home.
    pub fn take(&mut self, event_json: &str, now: u64) -> Result<(), String> {
        let statement = statement::read(event_json.as_bytes(), now).map_err(|e| e.to_string())?;
        let record = self.homes.get_mut(&statement.home).ok_or("no such home")?;
        record.home.take(statement.clone()).map_err(|e| e.to_string())?;
        // keep only the events that still fill a slot
        let held: Vec<[u8; 32]> = record.home.statements().map(|s| s.id).collect();
        record.events.push(event_json.to_string());
        record.events.retain(|e| statement::read(e.as_bytes(), u64::MAX / 2).is_ok_and(|s| held.contains(&s.id)));
        self.generation += 1;
        Ok(())
    }

    pub fn seal(&self, shares: &Shares) -> Vec<u8> {
        let stored = Stored {
            generation: self.generation,
            homes: self
                .homes
                .values()
                .map(|r| StoredHome { name: r.home.name.clone(), owner: hex::encode(r.home.owner), key: hex::encode(r.key), events: r.events.clone() })
                .collect(),
        };
        let mut plain = serde_json::to_vec(&stored).expect("state serializes");
        let mut nonce = [0u8; NONCE_LEN];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce).expect("random");
        shares
            .key()
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(MAGIC), &mut plain)
            .expect("AES-GCM seals the state");
        [MAGIC.as_slice(), &nonce, &plain].concat()
    }

    /// The state `sealed` holds, if it opens under `shares` and is not older
    /// than `held` (the generation this service last wrote, or 0).
    pub fn open(sealed: &[u8], shares: &Shares, held: u64) -> Result<State, Refused> {
        if sealed.len() > SEALED_BYTES_MAX || sealed.len() < MAGIC.len() + NONCE_LEN || &sealed[..8] != MAGIC {
            return Err(Refused::Malformed("its frame"));
        }
        let nonce: [u8; NONCE_LEN] = sealed[8..8 + NONCE_LEN].try_into().expect("12 bytes");
        let mut body = sealed[8 + NONCE_LEN..].to_vec();
        let plain = shares.key().open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(MAGIC), &mut body).map_err(|_| Refused::DoesNotOpen)?;
        let stored: Stored = serde_json::from_slice(plain).map_err(|_| Refused::Malformed("its JSON"))?;
        if stored.generation < held {
            return Err(Refused::Older { found: stored.generation, held });
        }
        let mut state = State { generation: stored.generation, homes: BTreeMap::new() };
        for h in stored.homes {
            let owner: [u8; 32] = hex::decode(&h.owner).ok().and_then(|o| o.try_into().ok()).ok_or(Refused::Malformed("an owner"))?;
            let key: [u8; 32] = hex::decode(&h.key).ok().and_then(|k| k.try_into().ok()).ok_or(Refused::Malformed("a key"))?;
            let mut home = Home::new(&h.name, owner);
            for event in &h.events {
                // signed statements, re-read: a state can only hold what the owner said
                let statement = statement::read(event.as_bytes(), u64::MAX / 2).map_err(|_| Refused::Malformed("a statement"))?;
                home.take(statement).map_err(|_| Refused::Malformed("a statement not its home's owner's"))?;
            }
            state.homes.insert(h.name.clone(), HomeRecord { home, key, events: h.events });
        }
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statement::{sign, tests::key, Says};

    fn shares(kms: u8, second: Option<u8>) -> Shares {
        Shares { kms: [kms; 32], second: second.map(|s| [s; 32]) }
    }

    fn state_with_a_rule() -> State {
        let mut state = State::default();
        state.add_home("h", key(1).verifying_key().to_bytes().into(), [5; 32]).unwrap();
        let event = sign(&key(1), "h", &Says::AcceptPublishedReleases { after_s: 86_400 }, 100, [0; 32]);
        state.take(&serde_json::to_string(&event).unwrap(), 100).unwrap();
        state
    }

    #[test]
    fn a_state_seals_and_opens_with_its_statements() {
        let state = state_with_a_rule();
        let opened = State::open(&state.seal(&shares(1, None)), &shares(1, None), 0).unwrap();
        assert_eq!(opened, state);
        assert_eq!(opened.home("h").unwrap().key, [5; 32]);
    }

    #[test]
    fn other_shares_open_nothing_and_a_second_share_cannot_be_dropped() {
        let sealed = state_with_a_rule().seal(&shares(1, Some(2)));
        assert!(State::open(&sealed, &shares(1, Some(2)), 0).is_ok());
        assert_eq!(State::open(&sealed, &shares(1, None), 0), Err(Refused::DoesNotOpen), "the second lock dropped");
        assert_eq!(State::open(&sealed, &shares(1, Some(3)), 0), Err(Refused::DoesNotOpen));
        assert_eq!(State::open(&sealed, &shares(9, Some(2)), 0), Err(Refused::DoesNotOpen));
    }

    #[test]
    fn an_older_state_is_refused() {
        let state = state_with_a_rule();
        let sealed = state.seal(&shares(1, None));
        assert_eq!(State::open(&sealed, &shares(1, None), state.generation + 1), Err(Refused::Older { found: state.generation, held: state.generation + 1 }));
        assert!(State::open(&sealed, &shares(1, None), state.generation).is_ok());
    }

    #[test]
    fn a_statement_by_another_person_is_not_taken() {
        let mut state = state_with_a_rule();
        let event = sign(&key(2), "h", &Says::Release { pcr0: "ab".repeat(48) }, 200, [0; 32]);
        assert!(state.take(&serde_json::to_string(&event).unwrap(), 200).is_err());
        assert_eq!(state.add_home("h", [0; 32], [0; 32]), Err(Refused::Exists));
    }
}
