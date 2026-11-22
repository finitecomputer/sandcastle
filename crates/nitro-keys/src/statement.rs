//! What an owner says, signed on their own device: nostr events (NIP-01),
//! the same keys the fragment CLI and the iPhone app already hold. Never a
//! browser's (docs/nitro-keys.md, "Statements"). Pure.
//!
//! A statement is a kind-30078 event (NIP-78, an application's own data,
//! replaceable by its `d` tag) whose `d` tag is `finite.home/<home>/<what>`
//! and whose content is one of [`Says`], as JSON. A newer statement with the
//! same `d` replaces the older; an older one never replaces a newer.

use k256::schnorr::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const KIND: u64 = 30078;
pub const D_PREFIX: &str = "finite.home/";
/// An event, at most, as JSON.
pub const EVENT_BYTES_MAX: usize = 8 * 1024;
/// A repair grant's length, at most: a repair is a visit, not a tenancy.
pub const REPAIR_SECONDS_MAX: u64 = 24 * 3600;
/// A statement dated this far ahead of the service's clock is refused.
pub const SKEW_SECONDS_MAX: u64 = 300;
pub const HOME_BYTES_MAX: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    Malformed(&'static str),
    /// The id is not the event's hash, or the signature is not its key's.
    Unsigned,
    NotAStatement(&'static str),
    Future,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Malformed(why) => write!(f, "not a nostr event: {why}"),
            Refused::Unsigned => f.write_str("the event's id or signature does not verify"),
            Refused::NotAStatement(why) => write!(f, "not a home's statement: {why}"),
            Refused::Future => f.write_str("the statement is dated in the future"),
        }
    }
}

impl std::error::Error for Refused {}

/// A NIP-01 event as it travels.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl Event {
    /// NIP-01's id: the hash of `[0, pubkey, created_at, kind, tags, content]`.
    pub fn computed_id(&self) -> [u8; 32] {
        let serialized = serde_json::to_string(&(0, &self.pubkey, self.created_at, self.kind, &self.tags, &self.content)).expect("an event serializes");
        Sha256::digest(serialized.as_bytes()).into()
    }

    /// Its id and its BIP-340 signature, checked.
    pub fn verify(&self) -> Result<[u8; 32], Refused> {
        let id = self.computed_id();
        if hex::decode(&self.id).ok().as_deref() != Some(id.as_slice()) {
            return Err(Refused::Unsigned);
        }
        let pubkey: [u8; 32] = hex::decode(&self.pubkey).ok().and_then(|k| k.try_into().ok()).ok_or(Refused::Malformed("pubkey"))?;
        let key = VerifyingKey::from_bytes(&pubkey).map_err(|_| Refused::Malformed("pubkey"))?;
        let sig = hex::decode(&self.sig).ok().and_then(|s| Signature::try_from(s.as_slice()).ok()).ok_or(Refused::Malformed("sig"))?;
        key.verify_raw(&id, &sig).map_err(|_| Refused::Unsigned)?;
        Ok(pubkey)
    }

    fn tag(&self, name: &str) -> Option<&str> {
        self.tags.iter().find(|t| t.first().map(String::as_str) == Some(name)).and_then(|t| t.get(1)).map(String::as_str)
    }
}

/// What an owner can say about their home.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "says", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Says {
    /// The default an owner's app signs once: release this home's key to an
    /// image Finite published in the public log at least `after_s` ago.
    AcceptPublishedReleases { after_s: u64 },
    /// Release this home's key to the image whose PCR0 this is, now.
    Release { pcr0: String },
    /// Let the person with this key repair the home until `until` (unix
    /// seconds): their session is named in the grant.
    Repair { to: String, until: u64 },
    /// Withdraw what the statement of this `d` said.
    Withdraw,
}

/// A statement, checked: who said it, about which home, what, when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub owner: [u8; 32],
    pub home: String,
    /// What the `d` tag names after the home: the slot a newer statement
    /// replaces.
    pub slot: String,
    pub says: Says,
    pub at: u64,
    pub id: [u8; 32],
}

pub fn valid_home(home: &str) -> bool {
    !home.is_empty() && home.len() <= HOME_BYTES_MAX && home.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn valid_pcr0(pcr0: &str) -> bool {
    pcr0.len() == 96 && pcr0.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// The slot each kind of statement fills: one rule, one release per PCR0,
/// one grant per person.
pub fn slot_of(says: &Says) -> String {
    match says {
        Says::AcceptPublishedReleases { .. } => "releases".into(),
        Says::Release { pcr0 } => format!("release/{pcr0}"),
        Says::Repair { to, .. } => format!("repair/{to}"),
        Says::Withdraw => String::new(),
    }
}

/// An event read and checked as a home's statement, at the service's `now`.
pub fn read(json: &[u8], now: u64) -> Result<Statement, Refused> {
    if json.len() > EVENT_BYTES_MAX {
        return Err(Refused::Malformed("longer than a statement may be"));
    }
    let event: Event = serde_json::from_slice(json).map_err(|_| Refused::Malformed("its JSON"))?;
    let owner = event.verify()?;
    if event.kind != KIND {
        return Err(Refused::NotAStatement("its kind"));
    }
    if event.created_at > now + SKEW_SECONDS_MAX {
        return Err(Refused::Future);
    }
    let d = event.tag("d").ok_or(Refused::NotAStatement("no d tag"))?;
    let (home, slot) = d.strip_prefix(D_PREFIX).and_then(|rest| rest.split_once('/')).ok_or(Refused::NotAStatement("its d tag"))?;
    if !valid_home(home) {
        return Err(Refused::NotAStatement("its home"));
    }
    let says: Says = serde_json::from_str(&event.content).map_err(|_| Refused::NotAStatement("its content"))?;
    match &says {
        Says::Release { pcr0 } if !valid_pcr0(pcr0) => return Err(Refused::NotAStatement("a PCR0 is 96 lowercase hex digits")),
        Says::Repair { to, until } => {
            if hex::decode(to).ok().filter(|k| k.len() == 32).is_none() {
                return Err(Refused::NotAStatement("a repair names a person's key, 32 bytes of hex"));
            }
            if until.saturating_sub(event.created_at) > REPAIR_SECONDS_MAX {
                return Err(Refused::NotAStatement("a repair is granted for at most a day"));
            }
        }
        _ => {}
    }
    if !matches!(says, Says::Withdraw) && slot != slot_of(&says) {
        return Err(Refused::NotAStatement("its d tag names another slot than its content"));
    }
    Ok(Statement { owner, home: home.to_string(), slot: slot.to_string(), says, at: event.created_at, id: event.computed_id() })
}

/// An event saying `says` about `home`, signed with `key`: what the CLI and
/// the app make. `key` is the person's nostr secret key.
#[cfg(any(test, feature = "sign"))]
pub fn sign(key: &k256::schnorr::SigningKey, home: &str, says: &Says, created_at: u64, aux: [u8; 32]) -> Event {
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let slot = match says {
        Says::Withdraw => panic!("a withdrawal names the slot it withdraws: use `sign_withdraw`"),
        says => slot_of(says),
    };
    finish(key, pubkey, home, &slot, serde_json::to_string(says).expect("a statement serializes"), created_at, aux)
}

#[cfg(any(test, feature = "sign"))]
pub fn sign_withdraw(key: &k256::schnorr::SigningKey, home: &str, slot: &str, created_at: u64, aux: [u8; 32]) -> Event {
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    finish(key, pubkey, home, slot, serde_json::to_string(&Says::Withdraw).expect("a statement serializes"), created_at, aux)
}

#[cfg(any(test, feature = "sign"))]
fn finish(key: &k256::schnorr::SigningKey, pubkey: String, home: &str, slot: &str, content: String, created_at: u64, aux: [u8; 32]) -> Event {
    let mut event = Event { id: String::new(), pubkey, created_at, kind: KIND, tags: vec![vec!["d".into(), format!("{D_PREFIX}{home}/{slot}")]], content, sig: String::new() };
    let id = event.computed_id();
    let sig = key.sign_raw(&id, &aux).expect("BIP-340 signs any digest");
    event.id = hex::encode(id);
    event.sig = hex::encode(sig.to_bytes());
    event
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn key(byte: u8) -> k256::schnorr::SigningKey {
        k256::schnorr::SigningKey::from_bytes(&[byte; 32]).unwrap()
    }

    fn json(event: &Event) -> Vec<u8> {
        serde_json::to_vec(event).unwrap()
    }

    #[test]
    fn a_signed_statement_reads_back() {
        let says = Says::AcceptPublishedReleases { after_s: 86_400 };
        let event = sign(&key(1), "home-1", &says, 1_000, [0; 32]);
        let s = read(&json(&event), 1_000).unwrap();
        assert_eq!((s.home.as_str(), s.slot.as_str(), &s.says, s.at), ("home-1", "releases", &says, 1_000));
        assert_eq!(s.owner, key(1).verifying_key().to_bytes().as_slice());
    }

    #[test]
    fn a_changed_or_unsigned_statement_is_refused() {
        let event = sign(&key(1), "home-1", &Says::Release { pcr0: "ab".repeat(48) }, 1_000, [0; 32]);
        let mut changed = event.clone();
        changed.content = serde_json::to_string(&Says::Release { pcr0: "cd".repeat(48) }).unwrap();
        assert_eq!(read(&json(&changed), 1_000), Err(Refused::Unsigned), "the content changed after signing");
        let mut moved = event.clone();
        moved.tags = vec![vec!["d".into(), format!("{D_PREFIX}home-2/release/{}", "ab".repeat(48))]];
        assert_eq!(read(&json(&moved), 1_000), Err(Refused::Unsigned), "the home changed after signing");
        let mut other = event.clone();
        other.pubkey = hex::encode(key(2).verifying_key().to_bytes());
        assert_eq!(read(&json(&other), 1_000), Err(Refused::Unsigned), "another person's key");
        assert_eq!(read(&json(&event), 1_000 - SKEW_SECONDS_MAX - 1), Err(Refused::Future));
    }

    #[test]
    fn statements_are_held_to_their_shapes() {
        let bad_pcr = sign(&key(1), "home-1", &Says::Release { pcr0: "AB".repeat(48) }, 1_000, [0; 32]);
        assert!(matches!(read(&json(&bad_pcr), 1_000), Err(Refused::NotAStatement(_))));
        let long = sign(&key(1), "home-1", &Says::Repair { to: hex::encode([2; 32]), until: 1_000 + REPAIR_SECONDS_MAX + 1 }, 1_000, [0; 32]);
        assert!(matches!(read(&json(&long), 1_000), Err(Refused::NotAStatement(_))));
        let day = sign(&key(1), "home-1", &Says::Repair { to: hex::encode([2; 32]), until: 1_000 + REPAIR_SECONDS_MAX }, 1_000, [0; 32]);
        assert!(read(&json(&day), 1_000).is_ok());
        let withdraw = sign_withdraw(&key(1), "home-1", "releases", 2_000, [0; 32]);
        assert_eq!(read(&json(&withdraw), 2_000).unwrap().slot, "releases");
        assert!(matches!(read(b"{}", 1_000), Err(Refused::Malformed(_))));
    }
}
