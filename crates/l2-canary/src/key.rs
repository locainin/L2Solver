use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{AgentId, CanaryIdentity, KeyError, MAX_KEY_LEN, MIN_KEY_LEN};

#[cfg(test)]
#[path = "../tests/key/internal.rs"]
mod internal_tests;

const SESSION_KEY_DOMAIN: &[u8] = b"l2solver:l2-canary-session-key:v1";

struct KeyMaterial {
    bytes: Zeroizing<[u8; MAX_KEY_LEN]>,
    length: u8,
}

impl KeyMaterial {
    fn new(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() < MIN_KEY_LEN {
            return Err(KeyError::TooShort {
                length: bytes.len(),
                min: MIN_KEY_LEN,
            });
        }
        if bytes.len() > MAX_KEY_LEN {
            return Err(KeyError::TooLong {
                length: bytes.len(),
                max: MAX_KEY_LEN,
            });
        }
        let mut material = Self {
            bytes: Zeroizing::new([0; MAX_KEY_LEN]),
            length: u8::try_from(bytes.len()).map_err(|_| KeyError::TooLong {
                length: bytes.len(),
                max: MAX_KEY_LEN,
            })?,
        };
        let destination = material
            .bytes
            .get_mut(..bytes.len())
            .ok_or(KeyError::InternalInvariant)?;
        destination.copy_from_slice(bytes);
        Ok(material)
    }

    fn as_bytes(&self) -> Result<&[u8], KeyError> {
        let length = usize::from(self.length);
        if !(MIN_KEY_LEN..=MAX_KEY_LEN).contains(&length) {
            return Err(KeyError::InternalInvariant);
        }
        self.bytes.get(..length).ok_or(KeyError::InternalInvariant)
    }
}

/// Unique long-term controller relationship key for one physical agent
///
/// This type cannot sign or verify canaries directly
pub struct AgentKey {
    agent_id: AgentId,
    material: KeyMaterial,
}

impl AgentKey {
    /// Construct a checked long-term agent relationship key
    ///
    /// # Errors
    ///
    /// Returns a key-size error when the input violates cryptographic bounds
    pub fn new(agent_id: AgentId, bytes: &[u8]) -> Result<Self, KeyError> {
        Ok(Self {
            agent_id,
            material: KeyMaterial::new(bytes)?,
        })
    }

    /// Return the physical agent identity bound to this relationship key
    #[must_use]
    pub const fn agent_id(&self) -> AgentId {
        self.agent_id
    }
}

/// Short-lived directional key for one assessment run
///
/// The type has no `Debug`, `Serialize`, `Display`, or `Clone` implementation
/// and clears its bytes when dropped
pub struct SessionKey {
    material: KeyMaterial,
    identity: CanaryIdentity,
}

impl SessionKey {
    /// Derive directional session material from one checked agent relationship
    ///
    /// # Errors
    ///
    /// Rejects an agent key that is not bound to the checked source identity
    pub fn derive(agent_key: &AgentKey, identity: &CanaryIdentity) -> Result<Self, KeyError> {
        if agent_key.agent_id != identity.source_agent_id() {
            return Err(KeyError::AgentKeyMismatch);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(agent_key.material.as_bytes()?)
            .map_err(|_| KeyError::DerivationFailed)?;
        mac.update(SESSION_KEY_DOMAIN);
        mac.update(identity.run_id().as_bytes());
        mac.update(identity.source_agent_id().as_bytes());
        mac.update(identity.destination_agent_id().as_bytes());
        let mut output = mac.finalize().into_bytes();
        let material = KeyMaterial::new(&output);
        output.zeroize();
        Ok(Self {
            material: material?,
            identity: *identity,
        })
    }

    pub(crate) fn as_bytes(&self) -> Result<&[u8], KeyError> {
        self.material.as_bytes()
    }

    pub(crate) const fn identity(&self) -> CanaryIdentity {
        self.identity
    }

    #[cfg(test)]
    pub(crate) fn malformed_for_test(identity: CanaryIdentity, length: u8) -> Self {
        Self {
            material: KeyMaterial {
                bytes: Zeroizing::new([0; MAX_KEY_LEN]),
                length,
            },
            identity,
        }
    }
}
