use std::error::Error;

use l2_canary::{
    AgentKey, Canary, CanaryIdentity, MIN_KEY_LEN, ReplayError, ReplayGuard, RunId, SessionKey,
    UnverifiedCanary, encode, verify,
};

const RUN: [u8; l2_canary::ID_LEN] = [0x10; l2_canary::ID_LEN];
const SOURCE: [u8; l2_canary::ID_LEN] = [0x20; l2_canary::ID_LEN];
const DESTINATION: [u8; l2_canary::ID_LEN] = [0x30; l2_canary::ID_LEN];

fn canary(sequence: u64) -> Result<Canary, Box<dyn Error>> {
    let run = RunId::from_recorded(RUN)?;
    let source = l2_canary::AgentId::new(SOURCE)?;
    let destination = l2_canary::AgentId::new(DESTINATION)?;
    let identity = CanaryIdentity::new(run, source, destination)?;
    Ok(Canary::new(
        identity,
        sequence,
        [0x40; l2_canary::NONCE_LEN],
    )?)
}

fn verified(sequence: u64) -> Result<l2_canary::VerifiedCanary, Box<dyn Error>> {
    let value = canary(sequence)?;
    let agent_key = AgentKey::new(value.source_agent_id(), &[0x5a; MIN_KEY_LEN])?;
    let key = SessionKey::derive(&agent_key, &value.identity())?;
    let wire = encode(&value, &key)?;
    Ok(verify(UnverifiedCanary::new(&wire), &key)?)
}

#[test]
fn max_sequence_not_change_state() -> Result<(), Box<dyn Error>> {
    let mut guard = ReplayGuard::new();
    assert_eq!(guard.accept(&verified(u64::MAX - 1)?), Ok(()));
    assert_eq!(guard.accept(&verified(u64::MAX)?), Ok(()));
    assert_eq!(
        guard.accept(&verified(u64::MAX - 1)?),
        Err(ReplayError::NonIncreasing {
            previous: u64::MAX,
            sequence: u64::MAX - 1,
        })
    );
    assert_eq!(guard.len(), 1);

    assert_eq!(
        Canary::new(canary(1)?.identity(), 0, [0x40; l2_canary::NONCE_LEN]),
        Err(l2_canary::CanaryError::ZeroSequence)
    );
    assert_eq!(guard.len(), 1);
    Ok(())
}
