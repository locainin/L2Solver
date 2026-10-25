use std::error::Error;

use l2_canary::{
    AgentId, AgentKey, Canary, CanaryIdentity, MIN_KEY_LEN, RunId, SessionKey, encode,
};
use l2_onpath::{CanaryExpectation, PathExpectation};

#[test]
fn checked_onpath_expectation_authenticated() -> Result<(), Box<dyn Error>> {
    let run = RunId::from_recorded([0x10; 16])?;
    let source = AgentId::new([0x20; 16])?;
    let destination = AgentId::new([0x30; 16])?;
    let identity = CanaryIdentity::new(run, source, destination)?;
    let canary = Canary::new(identity, 1, [0x40; 16])?;
    let expectation = CanaryExpectation::new(canary, PathExpectation::Forwarded, 1)?;
    let canary = expectation.canary();
    let agent_key = AgentKey::new(source, &[0x55; MIN_KEY_LEN])?;
    let key = SessionKey::derive(&agent_key, &canary.identity())?;
    assert!(encode(&canary, &key).is_ok());
    Ok(())
}
