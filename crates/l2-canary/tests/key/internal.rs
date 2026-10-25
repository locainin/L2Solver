use zeroize::Zeroizing;

use super::{KeyMaterial, SessionKey};
use crate::{AgentId, CanaryIdentity, ID_LEN, KeyError, MAX_KEY_LEN, RunId};

const MALFORMED_LENGTHS: [u8; 2] = [0, 65];

fn identity() -> Result<CanaryIdentity, Box<dyn std::error::Error>> {
    Ok(CanaryIdentity::new(
        RunId::from_recorded([1; ID_LEN])?,
        AgentId::new([2; ID_LEN])?,
        AgentId::new([3; ID_LEN])?,
    )?)
}

#[test]
fn malformed_private_error_empty_key() -> Result<(), Box<dyn std::error::Error>> {
    for length in MALFORMED_LENGTHS {
        let material = KeyMaterial {
            bytes: Zeroizing::new([0; MAX_KEY_LEN]),
            length,
        };
        let session = SessionKey {
            material,
            identity: identity()?,
        };

        assert_eq!(session.as_bytes(), Err(KeyError::InternalInvariant));
    }
    Ok(())
}
