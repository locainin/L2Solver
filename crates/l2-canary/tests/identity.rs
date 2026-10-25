use std::error::Error;

use l2_canary::{
    AgentId, AgentIdError, Canary, CanaryError, CanaryIdentity, CanaryIdentityError, RunId,
};

const RUN: [u8; l2_canary::ID_LEN] = [0x10; l2_canary::ID_LEN];
const SOURCE: [u8; l2_canary::ID_LEN] = [0x20; l2_canary::ID_LEN];
const DESTINATION: [u8; l2_canary::ID_LEN] = [0x30; l2_canary::ID_LEN];

fn run() -> Result<RunId, Box<dyn Error>> {
    Ok(RunId::from_recorded(RUN)?)
}

const fn agent(bytes: [u8; l2_canary::ID_LEN]) -> Result<AgentId, AgentIdError> {
    AgentId::new(bytes)
}

fn identity() -> Result<CanaryIdentity, Box<dyn Error>> {
    Ok(CanaryIdentity::new(
        run()?,
        agent(SOURCE)?,
        agent(DESTINATION)?,
    )?)
}

#[test]
fn agent_id_round_trips_bytes() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        AgentId::new([0; l2_canary::ID_LEN]),
        Err(AgentIdError::ReservedZero)
    );
    let value = agent(SOURCE)?;
    assert_eq!(value.bytes(), SOURCE);
    assert_eq!(value.as_bytes(), &SOURCE);
    Ok(())
}

#[test]
fn canary_identity_same_agent_direction() -> Result<(), Box<dyn Error>> {
    let source = agent(SOURCE)?;
    assert_eq!(
        CanaryIdentity::new(run()?, source, source),
        Err(CanaryIdentityError::SameAgent)
    );
    Ok(())
}

#[test]
fn canary_zero_sequence_fields() -> Result<(), Box<dyn Error>> {
    let identity = identity()?;
    assert_eq!(
        Canary::new(identity, 0, [0xa0; l2_canary::NONCE_LEN]),
        Err(CanaryError::ZeroSequence)
    );

    let canary = Canary::new(identity, 7, [0xa0; l2_canary::NONCE_LEN])?;
    assert_eq!(canary.run_id(), run()?);
    assert_eq!(canary.source_agent_id(), agent(SOURCE)?);
    assert_eq!(canary.destination_agent_id(), agent(DESTINATION)?);
    assert_eq!(canary.sequence(), 7);
    assert_eq!(canary.nonce(), [0xa0; l2_canary::NONCE_LEN]);
    assert_eq!(canary.identity(), identity);
    Ok(())
}
