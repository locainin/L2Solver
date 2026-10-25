use crate::{CanaryIdentity, MAX_REPLAY_IDENTITIES, ReplayError, VerifiedCanary};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReplayEntry {
    identity: CanaryIdentity,
    sequence: u64,
}

/// Bounded sequence tracking for authenticated canaries
///
/// The guard accepts only the opaque result of [`crate::verify`]
/// It stores identities and the newest sequence without payloads or secrets
#[derive(Clone, Debug, Default)]
pub struct ReplayGuard {
    entries: Vec<ReplayEntry>,
}

impl ReplayGuard {
    /// Create an empty guard
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Accept a sequence only when it increases for its identity tuple
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::NonIncreasing`] for a replay or stale sequence,
    /// or [`ReplayError::IdentityLimit`] when the bounded table is full
    pub fn accept(&mut self, canary: &VerifiedCanary) -> Result<(), ReplayError> {
        let identity = canary.identity();
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.identity == identity)
        {
            if canary.sequence() <= entry.sequence {
                return Err(ReplayError::NonIncreasing {
                    previous: entry.sequence,
                    sequence: canary.sequence(),
                });
            }
            entry.sequence = canary.sequence();
            return Ok(());
        }
        if self.entries.len() >= MAX_REPLAY_IDENTITIES {
            return Err(ReplayError::IdentityLimit {
                max: MAX_REPLAY_IDENTITIES,
            });
        }
        self.entries.push(ReplayEntry {
            identity,
            sequence: canary.sequence(),
        });
        Ok(())
    }

    /// Number of identity tuples currently retained
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no identity tuples have been accepted
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
