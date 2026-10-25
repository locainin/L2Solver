use super::support::{
    RUN, agent, input_with_rule, key, observation_claim, observe, packet_ref, record_transmit,
};
use l2_canary::{AgentId, Canary, CanaryIdentity, RunId};
use l2_segmentation::{
    DirectedRule, Evaluator, ObservationDisposition, ObservationRejection, PlanError, PlanInput,
    RuleExpectation, SegmentId,
};
use std::error::Error;

fn mismatch_fixture() -> Result<(Evaluator, Canary, Canary), Box<dyn Error>> {
    let mut input = PlanInput::for_replay(RUN)?;
    input.segments.extend([
        SegmentId::new(1),
        SegmentId::new(2),
        SegmentId::new(3),
        SegmentId::new(4),
    ]);
    input
        .agents
        .extend([agent(1, 1)?, agent(2, 2)?, agent(3, 3)?, agent(4, 4)?]);
    input.rules.extend([
        DirectedRule::new(
            SegmentId::new(1),
            SegmentId::new(2),
            RuleExpectation::Allow,
            1,
        ),
        DirectedRule::new(
            SegmentId::new(3),
            SegmentId::new(4),
            RuleExpectation::Allow,
            1,
        ),
    ]);
    let planned = l2_segmentation::plan(&input)?;
    let first = planned
        .probes()
        .first()
        .ok_or("missing first probe")?
        .canary()?;
    let second = planned
        .probes()
        .get(1)
        .ok_or("missing second probe")?
        .canary()?;
    Ok((Evaluator::new(&planned), first, second))
}

#[test]
fn wire_canary_is_verified() -> Result<(), Box<dyn Error>> {
    let planned = l2_segmentation::plan(&input_with_rule(RuleExpectation::Allow, 1)?)?;
    let key = key()?;
    let mut evaluator = Evaluator::new(&planned);
    let probe = planned.probes().first().ok_or("missing probe")?;
    let canary = probe.canary()?;
    let wire = l2_canary::encode(&canary, &key)?;
    record_transmit(&mut evaluator, &canary, &key, &wire)?;
    let (window, interface, observed_at) = observation_claim(&canary)?;
    assert_eq!(
        evaluator.observe_wire(
            &wire,
            &key,
            window,
            interface,
            observed_at,
            packet_ref(0x88, 80)?,
        )?,
        ObservationDisposition::Accepted
    );
    Ok(())
}

#[test]
fn wrong_nonce_is_ignored() -> Result<(), Box<dyn Error>> {
    let planned = l2_segmentation::plan(&input_with_rule(RuleExpectation::Allow, 1)?)?;
    let mut evaluator = Evaluator::new(&planned);
    let probe = planned.probes().first().ok_or("missing probe")?;
    let canary = probe.canary()?;
    let mut nonce = canary.nonce();
    nonce[0] ^= 1;
    let wrong_nonce = Canary::new(canary.identity(), canary.sequence(), nonce)?;
    assert_eq!(
        observe(&mut evaluator, &wrong_nonce, 81)?,
        ObservationDisposition::Ignored(ObservationRejection::WrongNonce)
    );
    Ok(())
}

#[test]
fn wrong_run_is_ignored() -> Result<(), Box<dyn Error>> {
    let planned = l2_segmentation::plan(&input_with_rule(RuleExpectation::Allow, 1)?)?;
    let mut evaluator = Evaluator::new(&planned);
    let probe = planned.probes().first().ok_or("missing probe")?;
    let canary = probe.canary()?;
    let mut run_id = canary.run_id().into_bytes();
    run_id[0] ^= 1;
    let wrong_identity = CanaryIdentity::new(
        RunId::from_recorded(run_id)?,
        canary.source_agent_id(),
        canary.destination_agent_id(),
    )?;
    let wrong_run = Canary::new(wrong_identity, canary.sequence(), canary.nonce())?;
    assert_eq!(
        observe(&mut evaluator, &wrong_run, 82)?,
        ObservationDisposition::Ignored(ObservationRejection::WrongRun)
    );
    Ok(())
}

#[test]
fn tampered_wire_is_rejected() -> Result<(), Box<dyn Error>> {
    let planned = l2_segmentation::plan(&input_with_rule(RuleExpectation::Allow, 1)?)?;
    let key = key()?;
    let mut evaluator = Evaluator::new(&planned);
    let probe = planned.probes().first().ok_or("missing probe")?;
    let canary = probe.canary()?;
    let wire = l2_canary::encode(&canary, &key)?;
    let (window, interface, observed_at) = observation_claim(&canary)?;

    let mut tampered = wire;
    tampered[0] ^= 1;
    assert!(
        evaluator
            .observe_wire(
                &tampered,
                &key,
                window,
                interface,
                observed_at,
                packet_ref(0x88, 83)?,
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn wrong_source_is_ignored() -> Result<(), Box<dyn Error>> {
    let (mut evaluator, first, _) = mismatch_fixture()?;
    let wrong_source_identity = CanaryIdentity::new(
        first.run_id(),
        AgentId::new([0xa1; 16])?,
        first.destination_agent_id(),
    )?;
    let wrong_source = Canary::new(wrong_source_identity, first.sequence(), first.nonce())?;
    assert_eq!(
        observe(&mut evaluator, &wrong_source, 101)?,
        ObservationDisposition::Ignored(ObservationRejection::WrongSource)
    );
    Ok(())
}

#[test]
fn wrong_destination_is_ignored() -> Result<(), Box<dyn Error>> {
    let (mut evaluator, first, _) = mismatch_fixture()?;
    let wrong_destination_identity = CanaryIdentity::new(
        first.run_id(),
        first.source_agent_id(),
        AgentId::new([0xb2; 16])?,
    )?;
    let wrong_destination =
        Canary::new(wrong_destination_identity, first.sequence(), first.nonce())?;
    assert_eq!(
        observe(&mut evaluator, &wrong_destination, 102)?,
        ObservationDisposition::Ignored(ObservationRejection::WrongDestination)
    );
    Ok(())
}

#[test]
fn wrong_direction_is_ignored() -> Result<(), Box<dyn Error>> {
    let (mut evaluator, first, second) = mismatch_fixture()?;
    let wrong_direction_identity = CanaryIdentity::new(
        first.run_id(),
        first.source_agent_id(),
        second.destination_agent_id(),
    )?;
    let wrong_direction = Canary::new(wrong_direction_identity, first.sequence(), first.nonce())?;
    assert_eq!(
        observe(&mut evaluator, &wrong_direction, 103)?,
        ObservationDisposition::Ignored(ObservationRejection::WrongDirection)
    );
    Ok(())
}

#[test]
fn wrong_sequence_is_ignored() -> Result<(), Box<dyn Error>> {
    let (mut evaluator, first, _) = mismatch_fixture()?;
    let wrong_sequence = Canary::new(first.identity(), 99, first.nonce())?;
    assert_eq!(
        observe(&mut evaluator, &wrong_sequence, 104)?,
        ObservationDisposition::Ignored(ObservationRejection::WrongSequence)
    );
    Ok(())
}

#[test]
fn planner_enforces_resource_bounds() -> Result<(), Box<dyn Error>> {
    assert!(agent(0, 1).is_err());

    let mut too_many_segments = PlanInput::for_replay(RUN)?;
    too_many_segments.segments.extend(
        (0_u16..=64)
            .filter_map(|value| u8::try_from(value).ok())
            .map(SegmentId::new),
    );
    assert!(matches!(
        l2_segmentation::plan(&too_many_segments),
        Err(PlanError::SegmentLimitExceeded { .. })
    ));

    let mut too_many_agents = PlanInput::for_replay(RUN)?;
    for value in 1_u16..=65 {
        too_many_agents.agents.push(agent(u8::try_from(value)?, 1)?);
    }
    assert!(matches!(
        l2_segmentation::plan(&too_many_agents),
        Err(PlanError::AgentLimitExceeded { .. })
    ));

    let bad_attempts = input_with_rule(RuleExpectation::Allow, 0)?;
    assert!(matches!(
        l2_segmentation::plan(&bad_attempts),
        Err(PlanError::AttemptsOutOfRange { .. })
    ));
    Ok(())
}
