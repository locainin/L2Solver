use super::write_at;
use crate::{AgentId, Canary, CanaryIdentity, ID_LEN, KeyError, NONCE_LEN, RunId, SessionKey};

#[test]
fn out_range_overflow_offsets() {
    let mut wire = [0_u8; 4];
    let value = [0xa5_u8; 2];

    assert_eq!(
        write_at(&mut wire, 3, &value),
        Err(KeyError::InternalInvariant)
    );
    assert_eq!(
        write_at(&mut wire, usize::MAX, &value),
        Err(KeyError::InternalInvariant)
    );
    assert_eq!(wire, [0; 4]);
}

#[test]
fn malformed_session_cannot_zero_tag() -> Result<(), Box<dyn std::error::Error>> {
    let identity = CanaryIdentity::new(
        RunId::from_recorded([1; ID_LEN])?,
        AgentId::new([2; ID_LEN])?,
        AgentId::new([3; ID_LEN])?,
    )?;
    let canary = Canary::new(identity, 1, [4; NONCE_LEN])?;
    for length in [0, 65] {
        let key = SessionKey::malformed_for_test(identity, length);
        assert_eq!(
            crate::encode(&canary, &key),
            Err(KeyError::InternalInvariant)
        );
    }
    Ok(())
}
