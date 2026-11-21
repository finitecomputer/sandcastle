//! The nonce ledger: nonces this verifier issued and has not yet seen
//! answered. A document must carry one of them, still live, and uses it
//! up, so a document recorded once cannot be played back
//! (attestation_process.md: a nonce is "a one-time token").
//!
//! It lives in memory on purpose. After a restart it knows no nonce, so a
//! document answering one from before is refused (fails closed) and the
//! guest simply asks again; persisting it would buy nothing but a replay
//! window across restarts.

use thiserror::Error;

use crate::AttestError;

pub const NONCE_BYTES: usize = 32;
/// Nonces outstanding at once: one per guest asking. Past it, issuing is
/// refused until some are answered or expire.
pub const NONCES_OUTSTANDING_MAX: usize = 256;
/// A nonce's life: a guest answers within its boot.
pub const NONCE_LIFE_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce(pub [u8; NONCE_BYTES]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IssueError {
    #[error("{0} nonces are outstanding, the most at once")]
    Full(usize),
    #[error("that nonce is already outstanding: the randomness repeated")]
    Repeated,
}

#[derive(Debug, Default)]
pub struct Nonces {
    /// Each outstanding nonce and when it expires (ms since the epoch).
    outstanding: Vec<(Nonce, u64)>,
}

impl Nonces {
    pub fn new() -> Nonces {
        Nonces { outstanding: Vec::with_capacity(NONCES_OUTSTANDING_MAX) }
    }

    /// Issues `fresh`, which the caller drew from a secure source (the
    /// ledger stays pure: no randomness, no clock of its own).
    pub fn issue(&mut self, fresh: [u8; NONCE_BYTES], now_ms: u64) -> Result<Nonce, IssueError> {
        self.outstanding.retain(|(_, expires_ms)| *expires_ms > now_ms);
        if self.outstanding.len() >= NONCES_OUTSTANDING_MAX {
            return Err(IssueError::Full(NONCES_OUTSTANDING_MAX));
        }
        let nonce = Nonce(fresh);
        if self.outstanding.iter().any(|(n, _)| *n == nonce) {
            return Err(IssueError::Repeated);
        }
        self.outstanding.push((nonce, now_ms + NONCE_LIFE_MS));
        assert!(self.outstanding.len() <= NONCES_OUTSTANDING_MAX);
        Ok(nonce)
    }

    /// Uses up `nonce`: present and live, or refused. Either way it is
    /// gone afterwards.
    pub(crate) fn redeem(&mut self, nonce: &[u8], now_ms: u64) -> Result<(), AttestError> {
        let Some(i) = self.outstanding.iter().position(|(n, _)| n.0.as_slice() == nonce) else {
            return Err(AttestError::NonceUnknown);
        };
        let (_, expires_ms) = self.outstanding.swap_remove(i);
        assert!(!self.outstanding.iter().any(|(n, _)| n.0.as_slice() == nonce), "never outstanding twice");
        if expires_ms > now_ms {
            Ok(())
        } else {
            Err(AttestError::NonceExpired)
        }
    }

    pub fn outstanding(&self) -> usize {
        self.outstanding.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(i: u32) -> [u8; NONCE_BYTES] {
        let mut b = [0u8; NONCE_BYTES];
        b[..4].copy_from_slice(&i.to_be_bytes());
        b
    }

    // Goal: a nonce redeems once, and only while live. Method: issue,
    // redeem, redeem again; issue, let it expire, redeem.
    #[test]
    fn once_and_only_while_live() {
        let mut n = Nonces::new();
        let a = n.issue(fresh(1), 1000).unwrap();
        assert_eq!(n.redeem(&a.0, 1001), Ok(()));
        assert_eq!(n.redeem(&a.0, 1002), Err(AttestError::NonceUnknown), "a replay");
        let b = n.issue(fresh(2), 1000).unwrap();
        assert_eq!(n.redeem(&b.0, 1000 + NONCE_LIFE_MS), Err(AttestError::NonceExpired));
        assert_eq!(n.redeem(&b.0, 1000), Err(AttestError::NonceUnknown), "used up even when refused");
        assert_eq!(n.redeem(&fresh(3), 1000), Err(AttestError::NonceUnknown), "never issued");
    }

    // Goal: the ledger is bounded, and expiry makes room. Method: fill it
    // to the limit, one past, then after the life.
    #[test]
    fn bounded_and_expiry_makes_room() {
        let mut n = Nonces::new();
        for i in 0..NONCES_OUTSTANDING_MAX as u32 {
            n.issue(fresh(i), 0).unwrap();
        }
        assert_eq!(n.issue(fresh(9999), 0), Err(IssueError::Full(NONCES_OUTSTANDING_MAX)));
        assert_eq!(n.issue(fresh(9999), NONCE_LIFE_MS).map(|x| x.0), Ok(fresh(9999)));
        assert_eq!(n.outstanding(), 1);
        assert_eq!(n.issue(fresh(9999), NONCE_LIFE_MS), Err(IssueError::Repeated));
    }
}
