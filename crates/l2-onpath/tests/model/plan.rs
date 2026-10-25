use std::error::Error;

use l2_canary::{AgentKey, Canary, CanaryIdentity, MIN_KEY_LEN, RunId, SessionKey};
use l2_onpath::{
    CanaryExpectation, CheckKind, ControlledEndpoint, InterfaceBindingRequest, MacAddress,
    NeighborBinding, PathExpectation, PlanError, Stimulus, StimulusId,
};

// Plan tests share compact identities while varying only the bounded collection under test
const fn agent(value: u8) -> Result<l2_onpath::AgentId, l2_onpath::AgentIdError> {
    l2_onpath::AgentId::new([value; l2_onpath::ID_LEN])
}

fn canary(
    run: u8,
    source: u8,
    destination: u8,
    sequence: u64,
    nonce: [u8; l2_onpath::NONCE_LEN],
) -> Result<Canary, Box<dyn Error>> {
    let identity = CanaryIdentity::new(
        RunId::from_recorded([run; l2_onpath::ID_LEN])?,
        agent(source)?,
        agent(destination)?,
    )?;
    Ok(Canary::new(identity, sequence, nonce)?)
}

fn endpoint(value: u8) -> Result<ControlledEndpoint, Box<dyn Error>> {
    Ok(ControlledEndpoint::new(
        NeighborBinding::new(
            agent(value)?,
            std::net::Ipv4Addr::new(192, 0, 2, value).into(),
            MacAddress::new([0x02, 0, 0, 0, 0, value])?,
        )?,
        InterfaceBindingRequest::new(1, 2, u32::from(value), 1)?,
    ))
}

#[test]
fn duplicate_checks_are_rejected() -> Result<(), Box<dyn Error>> {
    let mut plan = l2_onpath::AssessmentPlan::for_replay([1; l2_onpath::ID_LEN])?;
    plan.add_check(CheckKind::ArpSpoofSusceptibility)?;

    // Descriptor selection is a set even though plans retain insertion order
    assert_eq!(
        plan.add_check(CheckKind::ArpSpoofSusceptibility),
        Err(PlanError::DuplicateCheck {
            kind: CheckKind::ArpSpoofSusceptibility,
        })
    );
    Ok(())
}

#[test]
fn endpoint_limit_is_enforced() -> Result<(), Box<dyn Error>> {
    let mut plan = l2_onpath::AssessmentPlan::for_replay([4; l2_onpath::ID_LEN])?;

    // Fill the fixed endpoint collection before checking its next insertion
    for value in 1..=l2_onpath::MAX_ENDPOINTS {
        plan.add_endpoint(endpoint(u8::try_from(value)?)?)?;
    }

    // The first item over the bound reports both count and maximum
    assert_eq!(
        plan.add_endpoint(endpoint(u8::try_from(l2_onpath::MAX_ENDPOINTS + 1)?)?),
        Err(PlanError::EndpointLimitExceeded {
            count: l2_onpath::MAX_ENDPOINTS + 1,
            maximum: l2_onpath::MAX_ENDPOINTS,
        })
    );
    Ok(())
}

#[test]
fn stimulus_limits_references_checked() -> Result<(), Box<dyn Error>> {
    let mut plan = l2_onpath::AssessmentPlan::for_replay([5; l2_onpath::ID_LEN])?;
    plan.add_endpoint(endpoint(1)?)?;
    plan.add_check(CheckKind::ArpSpoofSusceptibility)?;

    // A stimulus must name an endpoint already present in the plan
    assert_eq!(
        plan.add_stimulus(Stimulus::new(
            1,
            CheckKind::ArpSpoofSusceptibility,
            agent(9)?,
            1,
        )?),
        Err(PlanError::UnknownEndpoint {
            endpoint: agent(9)?
        })
    );
    assert_eq!(
        plan.add_stimulus(Stimulus::new(
            1,
            CheckKind::ArpSpoofSusceptibility,
            agent(1)?,
            1,
        )?),
        Ok(())
    );

    // Stimulus identity and wire sequence each have independent uniqueness rules
    assert_eq!(
        plan.add_stimulus(Stimulus::new(
            1,
            CheckKind::ArpSpoofSusceptibility,
            agent(1)?,
            2,
        )?),
        Err(PlanError::DuplicateStimulus {
            id: StimulusId::new(1)?,
        })
    );
    assert_eq!(
        plan.add_stimulus(Stimulus::new(
            2,
            CheckKind::ArpSpoofSusceptibility,
            agent(1)?,
            1,
        )?),
        Err(PlanError::DuplicateStimulusSequence { sequence: 1 })
    );

    let mut full = l2_onpath::AssessmentPlan::for_replay([6; l2_onpath::ID_LEN])?;
    full.add_endpoint(endpoint(1)?)?;
    full.add_check(CheckKind::ArpSpoofSusceptibility)?;

    // A bounded plan accepts every documented stimulus slot
    for value in 1..=l2_onpath::MAX_STIMULI {
        let value = u16::try_from(value)?;
        full.add_stimulus(Stimulus::new(
            value,
            CheckKind::ArpSpoofSusceptibility,
            agent(1)?,
            u64::from(value),
        )?)?;
    }
    let extra = u16::try_from(l2_onpath::MAX_STIMULI + 1)?;
    assert_eq!(
        full.add_stimulus(Stimulus::new(
            extra,
            CheckKind::ArpSpoofSusceptibility,
            agent(1)?,
            u64::from(extra),
        )?),
        Err(PlanError::StimulusLimitExceeded {
            count: l2_onpath::MAX_STIMULI + 1,
            maximum: l2_onpath::MAX_STIMULI,
        })
    );
    Ok(())
}

#[test]
fn canary_references_are_checked() -> Result<(), Box<dyn Error>> {
    let mut plan = l2_onpath::AssessmentPlan::for_replay([7; l2_onpath::ID_LEN])?;
    plan.add_endpoint(endpoint(1)?)?;
    plan.add_endpoint(endpoint(2)?)?;
    plan.add_check(CheckKind::ArpSpoofSusceptibility)?;
    plan.add_stimulus(Stimulus::new(
        1,
        CheckKind::ArpSpoofSusceptibility,
        agent(1)?,
        1,
    )?)?;

    // Start with one valid expectation so each following mismatch is isolated
    let base = canary(7, 1, 2, 2, [1; l2_onpath::NONCE_LEN])?;
    plan.add_canary(CanaryExpectation::new(base, PathExpectation::Blocked, 1)?)?;

    // Canary references must point to a planned stimulus and known endpoints
    assert_eq!(
        plan.add_canary(CanaryExpectation::new(
            canary(7, 1, 2, 2, [2; l2_onpath::NONCE_LEN])?,
            PathExpectation::Blocked,
            2,
        )?),
        Err(PlanError::UnknownStimulus {
            id: StimulusId::new(2)?,
        })
    );
    assert_eq!(
        plan.add_canary(CanaryExpectation::new(base, PathExpectation::Blocked, 1)?),
        Err(PlanError::DuplicateCanary)
    );
    assert_eq!(
        plan.add_canary(CanaryExpectation::new(
            canary(7, 2, 1, 3, [5; l2_onpath::NONCE_LEN])?,
            PathExpectation::Blocked,
            1,
        )?),
        Err(PlanError::CanarySourceMismatch {
            expected: agent(1)?,
            actual: agent(2)?,
        })
    );
    assert_eq!(
        plan.add_canary(CanaryExpectation::new(
            canary(7, 9, 2, 2, [3; l2_onpath::NONCE_LEN])?,
            PathExpectation::Blocked,
            1,
        )?),
        Err(PlanError::UnknownEndpoint {
            endpoint: agent(9)?
        })
    );
    assert_eq!(
        plan.add_canary(CanaryExpectation::new(
            canary(7, 1, 9, 2, [4; l2_onpath::NONCE_LEN])?,
            PathExpectation::Blocked,
            1,
        )?),
        Err(PlanError::UnknownEndpoint {
            endpoint: agent(9)?
        })
    );
    Ok(())
}

#[test]
fn canary_limit_is_enforced() -> Result<(), Box<dyn Error>> {
    let mut plan = l2_onpath::AssessmentPlan::for_replay([8; l2_onpath::ID_LEN])?;
    plan.add_endpoint(endpoint(1)?)?;
    plan.add_endpoint(endpoint(2)?)?;
    plan.add_check(CheckKind::ArpSpoofSusceptibility)?;
    plan.add_stimulus(Stimulus::new(
        1,
        CheckKind::ArpSpoofSusceptibility,
        agent(1)?,
        1,
    )?)?;
    // Distinct sequence and nonce values fill the canary collection safely
    for value in 1..=l2_onpath::MAX_CANARIES {
        let sequence = u64::try_from(value)? + 1;
        let nonce = [u8::try_from(value % 256)?; l2_onpath::NONCE_LEN];
        plan.add_canary(CanaryExpectation::new(
            canary(8, 1, 2, sequence, nonce)?,
            PathExpectation::Blocked,
            1,
        )?)?;
    }
    let extra_nonce = [7; l2_onpath::NONCE_LEN];

    // The next expectation is rejected at the fixed collection boundary
    assert_eq!(
        plan.add_canary(CanaryExpectation::new(
            canary(8, 1, 2, 258, extra_nonce)?,
            PathExpectation::Blocked,
            1,
        )?),
        Err(PlanError::CanaryLimitExceeded {
            count: l2_onpath::MAX_CANARIES + 1,
            maximum: l2_onpath::MAX_CANARIES,
        })
    );
    Ok(())
}

#[test]
fn accepted_canary_derives_session_key() -> Result<(), Box<dyn Error>> {
    let mut plan = l2_onpath::AssessmentPlan::for_replay([9; l2_onpath::ID_LEN])?;
    plan.add_endpoint(endpoint(1)?)?;
    plan.add_endpoint(endpoint(2)?)?;
    plan.add_check(CheckKind::ArpSpoofSusceptibility)?;
    plan.add_stimulus(Stimulus::new(
        1,
        CheckKind::ArpSpoofSusceptibility,
        agent(1)?,
        1,
    )?)?;
    plan.add_stimulus(Stimulus::new(
        2,
        CheckKind::ArpSpoofSusceptibility,
        agent(2)?,
        4,
    )?)?;
    plan.add_canary(CanaryExpectation::new(
        canary(9, 1, 2, 2, [3; l2_onpath::NONCE_LEN])?,
        l2_onpath::PathExpectation::Forwarded,
        1,
    )?)?;
    plan.add_canary(CanaryExpectation::new(
        canary(9, 2, 1, 3, [4; l2_onpath::NONCE_LEN])?,
        l2_onpath::PathExpectation::Blocked,
        2,
    )?)?;

    // Every accepted expectation must be usable by the lower-level canary crate
    for expectation in plan.canaries() {
        let canary = expectation.canary();
        let agent_key = AgentKey::new(canary.source_agent_id(), &[0x42; MIN_KEY_LEN])?;
        assert!(SessionKey::derive(&agent_key, &canary.identity()).is_ok());
    }
    Ok(())
}
