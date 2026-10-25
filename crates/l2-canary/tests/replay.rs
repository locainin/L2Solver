use std::error::Error;

use l2_canary::{
    AgentId, AgentKey, Canary, CanaryIdentity, ReplayGuard, RunId, SessionKey, UnverifiedCanary,
    encode, verify,
};

fn canary(sequence: u64) -> Result<Canary, Box<dyn Error>> {
    let identity = CanaryIdentity::new(
        RunId::from_recorded([1; l2_canary::ID_LEN])?,
        AgentId::new([2; l2_canary::ID_LEN])?,
        AgentId::new([3; l2_canary::ID_LEN])?,
    )?;
    Ok(Canary::new(identity, sequence, [4; l2_canary::NONCE_LEN])?)
}

#[test]
fn reports_replay_guard_state() -> Result<(), Box<dyn Error>> {
    let mut guard = ReplayGuard::new();
    let value = canary(1)?;
    let agent_key = AgentKey::new(value.source_agent_id(), &[9; l2_canary::MIN_KEY_LEN])?;
    let key = SessionKey::derive(&agent_key, &value.identity())?;

    // A new guard has no identity rows
    assert!(guard.is_empty());
    assert_eq!(guard.len(), 0);

    // Accepting one canary creates the first row and clears the empty state
    let wire = encode(&value, &key)?;
    let verified = verify(UnverifiedCanary::new(&wire), &key)?;
    assert_eq!(guard.accept(&verified), Ok(()));
    assert!(!guard.is_empty());
    assert_eq!(guard.len(), 1);
    Ok(())
}
