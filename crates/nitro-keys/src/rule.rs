//! A home's rule: the statements its owner signed, and what they let the
//! key service do (docs/nitro-keys.md, "The release rule"). Pure.

use std::collections::BTreeMap;

use crate::statement::{Says, Statement};

/// A home's statements, at most: one rule, its releases and its grants.
pub const STATEMENTS_MAX: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// Signed by someone other than the home's owner.
    NotTheOwner,
    /// About another home.
    OtherHome,
    /// Not newer than the statement already in its slot.
    Stale,
    Full,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::NotTheOwner => f.write_str("the statement is not the home's owner's"),
            Refused::OtherHome => f.write_str("the statement is about another home"),
            Refused::Stale => f.write_str("a newer statement already fills its slot"),
            Refused::Full => write!(f, "the home holds its most statements ({STATEMENTS_MAX})"),
        }
    }
}

impl std::error::Error for Refused {}

/// Why a release was allowed, or why not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The owner named this PCR0.
    Named,
    /// The owner's rule took it: Finite published it at `at`, `after_s` ago
    /// or more.
    Published { at: u64 },
    /// The rule takes it, but not yet: it is released from `from`.
    NotYet { from: u64 },
    /// Nothing the owner signed covers it.
    No,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Home {
    pub name: String,
    pub owner: [u8; 32],
    slots: BTreeMap<String, Statement>,
}

impl Home {
    /// A home and its owner, bound when the home is made.
    pub fn new(name: &str, owner: [u8; 32]) -> Home {
        Home { name: name.to_string(), owner, slots: BTreeMap::new() }
    }

    /// Takes the owner's statement, in place of an older one in its slot.
    pub fn take(&mut self, statement: Statement) -> Result<(), Refused> {
        if statement.home != self.name {
            return Err(Refused::OtherHome);
        }
        if statement.owner != self.owner {
            return Err(Refused::NotTheOwner);
        }
        if self.slots.get(&statement.slot).is_some_and(|held| (held.at, held.id) >= (statement.at, statement.id)) {
            return Err(Refused::Stale);
        }
        if !self.slots.contains_key(&statement.slot) && self.slots.len() >= STATEMENTS_MAX {
            return Err(Refused::Full);
        }
        self.slots.insert(statement.slot.clone(), statement);
        Ok(())
    }

    fn says(&self, slot: &str) -> Option<&Says> {
        self.slots.get(slot).map(|s| &s.says).filter(|says| !matches!(says, Says::Withdraw))
    }

    /// Whether the home's key may go to the image whose PCR0 is `pcr0`, which
    /// the public log shows Finite published at `published` (when it does).
    pub fn may_release(&self, pcr0: &str, published: Option<u64>, now: u64) -> Decision {
        if matches!(self.says(&format!("release/{pcr0}")), Some(Says::Release { .. })) {
            return Decision::Named;
        }
        match (self.says("releases"), published) {
            (Some(Says::AcceptPublishedReleases { after_s }), Some(at)) => {
                let from = at.saturating_add(*after_s);
                if now >= from {
                    Decision::Published { at }
                } else {
                    Decision::NotYet { from }
                }
            }
            _ => Decision::No,
        }
    }

    /// Until when `person` may repair the home, if they may now.
    pub fn repair_until(&self, person: &[u8; 32], now: u64) -> Option<u64> {
        match self.says(&format!("repair/{}", hex::encode(person))) {
            Some(Says::Repair { until, .. }) if now < *until => Some(*until),
            _ => None,
        }
    }

    pub fn statements(&self) -> impl Iterator<Item = &Statement> {
        self.slots.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statement::{self, tests::key};

    fn said(byte: u8, home: &str, says: &Says, at: u64) -> Statement {
        let event = statement::sign(&key(byte), home, says, at, [0; 32]);
        statement::read(&serde_json::to_vec(&event).unwrap(), at).unwrap()
    }

    fn owner(byte: u8) -> [u8; 32] {
        key(byte).verifying_key().to_bytes().into()
    }

    const PCR: &str = "ab";

    fn pcr() -> String {
        PCR.repeat(48)
    }

    #[test]
    fn nothing_signed_releases_nothing() {
        assert_eq!(Home::new("h", owner(1)).may_release(&pcr(), Some(0), 1_000_000), Decision::No);
    }

    #[test]
    fn the_default_rule_waits_its_day_after_publication() {
        let mut home = Home::new("h", owner(1));
        home.take(said(1, "h", &Says::AcceptPublishedReleases { after_s: 86_400 }, 100)).unwrap();
        assert_eq!(home.may_release(&pcr(), None, 1_000_000), Decision::No, "an image Finite never published");
        assert_eq!(home.may_release(&pcr(), Some(1_000), 1_000 + 86_399), Decision::NotYet { from: 87_400 });
        assert_eq!(home.may_release(&pcr(), Some(1_000), 87_400), Decision::Published { at: 1_000 });
    }

    #[test]
    fn a_named_release_needs_no_log() {
        let mut home = Home::new("h", owner(1));
        home.take(said(1, "h", &Says::Release { pcr0: pcr() }, 100)).unwrap();
        assert_eq!(home.may_release(&pcr(), None, 200), Decision::Named);
        assert_eq!(home.may_release(&"cd".repeat(48), None, 200), Decision::No);
    }

    #[test]
    fn only_the_owner_speaks_and_only_newer_statements_replace() {
        let mut home = Home::new("h", owner(1));
        assert_eq!(home.take(said(2, "h", &Says::Release { pcr0: pcr() }, 100)), Err(Refused::NotTheOwner));
        assert_eq!(home.take(said(1, "other", &Says::Release { pcr0: pcr() }, 100)), Err(Refused::OtherHome));
        home.take(said(1, "h", &Says::AcceptPublishedReleases { after_s: 10 }, 100)).unwrap();
        assert_eq!(home.take(said(1, "h", &Says::AcceptPublishedReleases { after_s: 0 }, 50)), Err(Refused::Stale), "an older statement replayed");
        let withdraw = statement::sign_withdraw(&key(1), "h", "releases", 200, [0; 32]);
        home.take(statement::read(&serde_json::to_vec(&withdraw).unwrap(), 200).unwrap()).unwrap();
        assert_eq!(home.may_release(&pcr(), Some(0), 1_000), Decision::No, "the rule withdrawn");
        assert_eq!(home.take(said(1, "h", &Says::AcceptPublishedReleases { after_s: 0 }, 150)), Err(Refused::Stale), "the withdrawal is newer");
    }

    #[test]
    fn a_repair_grant_ends_on_time() {
        let mut home = Home::new("h", owner(1));
        let person = [7u8; 32];
        home.take(said(1, "h", &Says::Repair { to: hex::encode(person), until: 1_000 }, 100)).unwrap();
        assert_eq!(home.repair_until(&person, 999), Some(1_000));
        assert_eq!(home.repair_until(&person, 1_000), None);
        assert_eq!(home.repair_until(&[8u8; 32], 500), None, "another person");
    }
}
