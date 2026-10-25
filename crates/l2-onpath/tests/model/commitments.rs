use std::error::Error;

use l2_canary::{AgentKey, Canary, CanaryIdentity, MIN_KEY_LEN, RunId, SessionKey, encode};
use l2_onpath::{
    CheckKind, InterfaceBindingRequest, PlanError, PlannedCanaryFrame, Stimulus, TxCommitment,
};

mod plan_fixture {
    use super::*;

    pub const RUN: [u8; l2_onpath::ID_LEN] = [0x31; l2_onpath::ID_LEN];

    pub fn interface() -> Result<InterfaceBindingRequest, Box<dyn Error>> {
        Ok(InterfaceBindingRequest::new(1, 2, 3, 1)?)
    }

    pub fn frame(sequence: u64, marker: u8) -> Vec<u8> {
        let mut frame = Vec::with_capacity(22);
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, marker]);
        frame.extend_from_slice(&[0x02, 0, 0, 0, 1, marker]);
        frame.extend_from_slice(&0x0800_u16.to_be_bytes());
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame
    }

    pub fn frame_commitment(
        run: [u8; l2_onpath::ID_LEN],
        sequence: u64,
        marker: u8,
    ) -> Result<TxCommitment, Box<dyn Error>> {
        frame_commitment_on(run, sequence, marker, interface()?)
    }

    pub fn frame_commitment_on(
        run: [u8; l2_onpath::ID_LEN],
        sequence: u64,
        marker: u8,
        interface: InterfaceBindingRequest,
    ) -> Result<TxCommitment, Box<dyn Error>> {
        Ok(TxCommitment::from_frame_claim(
            run,
            sequence,
            interface,
            &frame(sequence, marker),
        )?)
    }

    pub fn cleanup_commitment(
        endpoint: l2_onpath::ControlledEndpoint,
        sequence: u64,
    ) -> Result<TxCommitment, Box<dyn Error>> {
        frame_commitment_on(RUN, sequence, 0x70, endpoint.interface())
    }

    pub fn canary_commitment(canary: Canary) -> Result<TxCommitment, Box<dyn Error>> {
        let key = SessionKey::derive(
            &AgentKey::new(canary.source_agent_id(), &[0x52; MIN_KEY_LEN])?,
            &canary.identity(),
        )?;
        let payload = encode(&canary, &key)?;
        let mut frame = Vec::with_capacity(14 + payload.len());
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        frame.extend_from_slice(&l2_canary::ETHER_TYPE.to_be_bytes());
        frame.extend_from_slice(&payload);
        let planned = PlannedCanaryFrame::from_canary(canary, &key, &frame)?;
        Ok(TxCommitment::from_planned_frame(&planned, interface()?))
    }

    pub const fn agent(value: u8) -> Result<l2_onpath::AgentId, l2_onpath::AgentIdError> {
        l2_onpath::AgentId::new([value; l2_onpath::ID_LEN])
    }

    pub fn canary(
        source: u8,
        destination: u8,
        sequence: u64,
        nonce: [u8; l2_onpath::NONCE_LEN],
    ) -> Result<Canary, Box<dyn Error>> {
        let identity = CanaryIdentity::new(
            RunId::from_recorded(RUN)?,
            agent(source)?,
            agent(destination)?,
        )?;
        Ok(Canary::new(identity, sequence, nonce)?)
    }

    pub fn endpoint(value: u8) -> Result<l2_onpath::ControlledEndpoint, Box<dyn Error>> {
        Ok(l2_onpath::ControlledEndpoint::new(
            l2_onpath::NeighborBinding::new(
                agent(value)?,
                std::net::Ipv4Addr::new(192, 0, 2, value).into(),
                l2_onpath::MacAddress::new([0x02, 0, 0, 0, 0, value])?,
            )?,
            InterfaceBindingRequest::new(1, 2, u32::from(value) + 2, 1)?,
        ))
    }

    pub fn base() -> Result<l2_onpath::AssessmentPlan, Box<dyn Error>> {
        let mut plan = l2_onpath::AssessmentPlan::for_replay(RUN)?;
        plan.add_endpoint(endpoint(1)?)?;
        plan.add_endpoint(endpoint(2)?)?;
        plan.add_check(CheckKind::ArpSpoofSusceptibility)?;
        plan.add_stimulus(Stimulus::new(
            1,
            CheckKind::ArpSpoofSusceptibility,
            agent(1)?,
            11,
        )?)?;
        plan.add_canary(l2_onpath::CanaryExpectation::new(
            plan_fixture::canary(1, 2, 12, [7; l2_onpath::NONCE_LEN])?,
            l2_onpath::PathExpectation::Blocked,
            1,
        )?)?;
        Ok(plan)
    }
}

#[test]
fn commitment_requires_a_planned_sequence() -> Result<(), Box<dyn Error>> {
    let mut plan = plan_fixture::base()?;

    assert_eq!(
        plan.add_commitment(plan_fixture::frame_commitment(plan_fixture::RUN, 99, 1)?),
        Err(PlanError::UnknownCommitmentSequence { sequence: 99 })
    );
    assert_eq!(
        plan.add_commitment(plan_fixture::frame_commitment(
            [8; l2_onpath::ID_LEN],
            11,
            1,
        )?),
        Err(PlanError::WrongRun)
    );
    Ok(())
}

#[test]
fn commitment_rejects_duplicates_and_conflicts() -> Result<(), Box<dyn Error>> {
    let mut plan = plan_fixture::base()?;
    let commitment = plan_fixture::frame_commitment(plan_fixture::RUN, 11, 1)?;
    plan.add_commitment(commitment)?;

    assert_eq!(
        plan.add_commitment(commitment),
        Err(PlanError::DuplicateCommitment { sequence: 11 })
    );
    assert_eq!(
        plan.add_commitment(plan_fixture::frame_commitment(plan_fixture::RUN, 11, 2)?),
        Err(PlanError::ConflictingCommitment { sequence: 11 })
    );
    Ok(())
}

#[test]
fn commitment_covers_stimulus_canary_sequences() -> Result<(), Box<dyn Error>> {
    let mut plan = plan_fixture::base()?;
    let stimulus = plan_fixture::frame_commitment(plan_fixture::RUN, 11, 1)?;
    let canary = plan_fixture::canary_commitment(plan_fixture::canary(
        1,
        2,
        12,
        [7; l2_onpath::NONCE_LEN],
    )?)?;
    plan.add_commitment(stimulus)?;
    plan.add_commitment(canary)?;

    assert_eq!(plan.commitment(11), Some(stimulus));
    assert_eq!(plan.commitment(12), Some(canary));
    assert_eq!(plan.commitments().count(), 2);
    assert_eq!(
        l2_onpath::MAX_COMMITMENTS,
        l2_onpath::MAX_STIMULI + l2_onpath::MAX_CANARIES + l2_onpath::MAX_ENDPOINTS
    );
    Ok(())
}

#[test]
fn cleanup_commitments_endpoint_scoped_resolvable() -> Result<(), Box<dyn Error>> {
    let mut plan = plan_fixture::base()?;
    let first = plan_fixture::endpoint(1)?;
    let second = plan_fixture::endpoint(2)?;
    let first_cleanup = plan_fixture::cleanup_commitment(first, 13)?;
    let second_cleanup = plan_fixture::cleanup_commitment(second, 14)?;

    plan.add_cleanup_commitment(first.id(), first.family(), first_cleanup)?;
    plan.add_cleanup_commitment(second.id(), second.family(), second_cleanup)?;

    assert_eq!(
        plan.cleanup_commitment(first.id(), first.family()),
        Some(first_cleanup)
    );
    assert_eq!(
        plan.cleanup_commitment(second.id(), second.family()),
        Some(second_cleanup)
    );
    assert_eq!(plan.commitment(13), Some(first_cleanup));
    assert_eq!(plan.commitment(14), Some(second_cleanup));
    assert_eq!(plan.commitments().count(), 2);
    Ok(())
}

#[test]
fn commitments_follow_global_sequence() -> Result<(), Box<dyn Error>> {
    let mut plan = plan_fixture::base()?;
    let first = plan_fixture::endpoint(1)?;
    let second = plan_fixture::endpoint(2)?;
    plan.add_commitment(plan_fixture::frame_commitment(plan_fixture::RUN, 11, 1)?)?;
    plan.add_commitment(plan_fixture::canary_commitment(plan_fixture::canary(
        1,
        2,
        12,
        [7; l2_onpath::NONCE_LEN],
    )?)?)?;
    plan.add_cleanup_commitment(
        first.id(),
        first.family(),
        plan_fixture::cleanup_commitment(first, 10)?,
    )?;
    plan.add_cleanup_commitment(
        second.id(),
        second.family(),
        plan_fixture::cleanup_commitment(second, 13)?,
    )?;

    let sequences = plan
        .commitments()
        .map(TxCommitment::sequence)
        .collect::<Vec<_>>();
    assert_eq!(sequences, vec![10, 11, 12, 13]);
    Ok(())
}

#[test]
fn cleanup_commitments_interface_reused_sequences() -> Result<(), Box<dyn Error>> {
    let mut plan = plan_fixture::base()?;
    let first = plan_fixture::endpoint(1)?;
    let wrong_interface = plan_fixture::frame_commitment_on(
        plan_fixture::RUN,
        13,
        0x70,
        InterfaceBindingRequest::new(1, 2, 99, 1)?,
    )?;
    assert_eq!(
        plan.add_cleanup_commitment(first.id(), first.family(), wrong_interface),
        Err(PlanError::CommitmentInterfaceMismatch { sequence: 13 })
    );

    let conflicting = plan_fixture::cleanup_commitment(first, 11)?;
    assert_eq!(
        plan.add_cleanup_commitment(first.id(), first.family(), conflicting),
        Err(PlanError::DuplicateCommitment { sequence: 11 })
    );
    Ok(())
}

#[test]
fn canary_sequence_generic_frame() -> Result<(), Box<dyn Error>> {
    let mut plan = plan_fixture::base()?;
    let generic = plan_fixture::frame_commitment(plan_fixture::RUN, 12, 3)?;

    assert_eq!(
        plan.add_commitment(generic),
        Err(PlanError::CommitmentCanaryMismatch { sequence: 12 })
    );
    Ok(())
}

#[test]
fn canary_commitment_source_endpoint_interface() -> Result<(), Box<dyn Error>> {
    let mut plan = plan_fixture::base()?;
    let canary = plan_fixture::canary(1, 2, 12, [7; l2_onpath::NONCE_LEN])?;
    let key = SessionKey::derive(
        &AgentKey::new(canary.source_agent_id(), &[0x52; MIN_KEY_LEN])?,
        &canary.identity(),
    )?;
    let payload = encode(&canary, &key)?;
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&l2_canary::ETHER_TYPE.to_be_bytes());
    frame.extend_from_slice(&payload);
    let planned = PlannedCanaryFrame::from_canary(canary, &key, &frame)?;
    let wrong =
        TxCommitment::from_planned_frame(&planned, InterfaceBindingRequest::new(1, 2, 99, 1)?);

    assert_eq!(
        plan.add_commitment(wrong),
        Err(PlanError::CommitmentInterfaceMismatch { sequence: 12 })
    );
    assert!(plan.commitment(12).is_none());
    Ok(())
}

#[test]
fn stimulus_commitment_target_endpoint_interface() -> Result<(), Box<dyn Error>> {
    let mut plan = plan_fixture::base()?;
    let wrong = plan_fixture::frame_commitment_on(
        plan_fixture::RUN,
        11,
        1,
        InterfaceBindingRequest::new(1, 2, 99, 1)?,
    )?;

    assert_eq!(
        plan.add_commitment(wrong),
        Err(PlanError::CommitmentInterfaceMismatch { sequence: 11 })
    );
    assert!(plan.commitment(11).is_none());
    Ok(())
}

#[test]
fn transmit_sequences_are_globally_unique() -> Result<(), Box<dyn Error>> {
    let mut plan = plan_fixture::base()?;
    let duplicate_canary_sequence = Stimulus::new(
        2,
        CheckKind::ArpSpoofSusceptibility,
        plan_fixture::agent(1)?,
        12,
    )?;
    assert_eq!(
        plan.add_stimulus(duplicate_canary_sequence),
        Err(PlanError::DuplicateTransmitSequence { sequence: 12 })
    );

    let duplicate_stimulus_sequence = l2_onpath::CanaryExpectation::new(
        plan_fixture::canary(1, 2, 11, [8; l2_onpath::NONCE_LEN])?,
        l2_onpath::PathExpectation::Blocked,
        1,
    )?;
    assert_eq!(
        plan.add_canary(duplicate_stimulus_sequence),
        Err(PlanError::DuplicateTransmitSequence { sequence: 11 })
    );

    let duplicate_canary = l2_onpath::CanaryExpectation::new(
        plan_fixture::canary(1, 2, 12, [9; l2_onpath::NONCE_LEN])?,
        l2_onpath::PathExpectation::Blocked,
        1,
    )?;
    assert_eq!(
        plan.add_canary(duplicate_canary),
        Err(PlanError::DuplicateTransmitSequence { sequence: 12 })
    );

    // Sequence uniqueness applies across directions, identities, and nonce material
    plan.add_stimulus(Stimulus::new(
        2,
        CheckKind::ArpSpoofSusceptibility,
        plan_fixture::agent(2)?,
        13,
    )?)?;
    let duplicate_sequence_other_direction = l2_onpath::CanaryExpectation::new(
        plan_fixture::canary(2, 1, 12, [10; l2_onpath::NONCE_LEN])?,
        l2_onpath::PathExpectation::Blocked,
        2,
    )?;
    assert_eq!(
        plan.add_canary(duplicate_sequence_other_direction),
        Err(PlanError::DuplicateTransmitSequence { sequence: 12 })
    );
    Ok(())
}
