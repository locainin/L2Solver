use core::fmt;

use crate::ID_LEN;

/// Fresh identity that scopes one assessment run
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunId([u8; ID_LEN]);

impl RunId {
    /// Generate a fresh identity with the operating system CSPRNG
    ///
    /// # Errors
    ///
    /// Returns an entropy error when the operating system cannot fill the ID
    pub fn generate() -> Result<Self, RunIdError> {
        let mut bytes = [0; ID_LEN];
        getrandom::fill(&mut bytes).map_err(RunIdError::Entropy)?;
        Self::from_recorded(bytes)
    }

    /// Restore an identity from authoritative recorded evidence
    ///
    /// This constructor exists for replay and deterministic tests
    ///
    /// # Errors
    ///
    /// Rejects the all-zero sentinel
    pub fn from_recorded(bytes: [u8; ID_LEN]) -> Result<Self, RunIdError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RunIdError::ReservedZero);
        }
        Ok(Self(bytes))
    }

    /// Borrow the authenticated wire bytes
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }

    /// Copy the authenticated wire bytes
    #[must_use]
    pub const fn into_bytes(self) -> [u8; ID_LEN] {
        self.0
    }
}

/// Failure to create a valid assessment run identity
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunIdError {
    /// Operating-system entropy was unavailable
    Entropy(getrandom::Error),
    /// The all-zero value is reserved as an invalid sentinel
    ReservedZero,
}

impl fmt::Display for RunIdError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy(error) => write!(output, "could not generate assessment run ID: {error}"),
            Self::ReservedZero => output.write_str("assessment run ID must not be all zeroes"),
        }
    }
}

impl std::error::Error for RunIdError {}
