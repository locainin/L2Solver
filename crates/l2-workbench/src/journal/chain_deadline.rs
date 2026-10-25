use serde::{Deserialize, Serialize};

/// Wall-clock budget for finding event chains; JSON null disables the deadline
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainDeadline(Option<u64>);

impl ChainDeadline {
    /// Limit chain work to the given number of milliseconds
    #[must_use]
    pub const fn limited(milliseconds: u64) -> Self {
        Self(Some(milliseconds))
    }

    /// Allow chain work without a wall-clock deadline
    #[must_use]
    pub const fn unlimited() -> Self {
        Self(None)
    }

    /// Return the millisecond budget, or None when the deadline is disabled
    #[must_use]
    pub const fn milliseconds(self) -> Option<u64> {
        self.0
    }
}

impl Default for ChainDeadline {
    fn default() -> Self {
        // Omitted plan deadlines bound work to two minutes
        Self::limited(120_000)
    }
}
