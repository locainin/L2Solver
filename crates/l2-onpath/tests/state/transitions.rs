use std::{error::Error, net::Ipv6Addr};

use l2_onpath::{
    AddressFamily, AssessmentPlan, AssessmentSession, CheckKind, ControlledEndpoint, MacAddress,
    NeighborBinding, NeighborDisposition, NeighborTransitionReceipt, ObservationWindowReceipt,
    ReceiptError, SessionError, Stimulus, StimulusReceipt,
};

use super::support::{
    RUN, Scenario, advance_to_armed, agent, cleanup_commitment, endpoint, endpoint_interface,
    packet_ref, stimulus_commitment, tx, window_timing,
};

#[test]
fn window_must_cover_the_stimulus() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_armed(&mut session, &scenario.plan)?;
    session.record_stimulus(
        StimulusReceipt::new(
            RUN,
            scenario.stimulus.id(),
            tx(scenario.stimulus)?,
            packet_ref(0xa1, 1)?,
        )?,
        super::support::budget_time(4)?,
    )?;
    let late_window = ObservationWindowReceipt::new(
        RUN,
        scenario.stimulus.sequence(),
        agent(1)?,
        endpoint_interface(1)?,
        window_timing(scenario.stimulus.sequence(), (16, 21), (14, 15, 17))?,
        0,
        true,
    )?;
    let transition = NeighborTransitionReceipt::new(
        RUN,
        scenario.stimulus.id(),
        AddressFamily::Ipv4,
        NeighborDisposition::ConflictRejected,
        late_window,
    )?;

    // A transition without the transmit inside its window cannot be attributed
    assert!(
        session
            .record_transition(transition, super::support::budget_time(5)?)
            .is_err()
    );
    Ok(())
}

#[test]
fn transition_requires_interface_without_mutation() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_armed(&mut session, &scenario.plan)?;
    session.record_stimulus(
        StimulusReceipt::new(
            RUN,
            scenario.stimulus.id(),
            tx(scenario.stimulus)?,
            packet_ref(0xa1, 1)?,
        )?,
        super::support::budget_time(4)?,
    )?;
    let wrong_window = ObservationWindowReceipt::new(
        RUN,
        scenario.stimulus.sequence(),
        agent(1)?,
        l2_onpath::InterfaceBindingRequest::new(1, 2, 99, 1)?,
        window_timing(scenario.stimulus.sequence(), (10, 21), (11, 15, 17))?,
        0,
        true,
    )?;
    let transition = NeighborTransitionReceipt::new(
        RUN,
        scenario.stimulus.id(),
        AddressFamily::Ipv4,
        NeighborDisposition::ConflictRejected,
        wrong_window,
    )?;

    assert!(matches!(
        session.record_transition(transition, super::support::budget_time(5)?),
        Err(SessionError::Receipt(
            ReceiptError::ObservationInterfaceMismatch
        ))
    ));
    assert_eq!(
        session.phase(),
        l2_onpath::AssessmentPhase::StimuliCommitted
    );
    session.record_transition(
        super::support::transition(scenario.stimulus, NeighborDisposition::ConflictRejected, 0)?,
        super::support::budget_time(5)?,
    )?;
    assert_eq!(
        session.phase(),
        l2_onpath::AssessmentPhase::TransitionsRecorded
    );
    Ok(())
}

#[test]
fn transition_boundaries_families_checked() -> Result<(), Box<dyn Error>> {
    let first = ControlledEndpoint::new(
        NeighborBinding::new(
            agent(1)?,
            "2001:db8::1".parse::<Ipv6Addr>()?.into(),
            MacAddress::new([0x02, 0, 0, 0, 1, 1])?,
        )?,
        endpoint_interface(1)?,
    );
    let second = endpoint(1, 2)?;
    let stimulus = Stimulus::new(1, CheckKind::ArpSpoofSusceptibility, agent(1)?, 1)?;
    let mut plan = AssessmentPlan::for_replay(RUN)?;
    plan.add_endpoint(first)?;
    plan.add_endpoint(second)?;
    plan.add_check(CheckKind::ArpSpoofSusceptibility)?;
    plan.add_stimulus(stimulus)?;
    plan.add_commitment(stimulus_commitment(1)?)?;
    plan.add_cleanup_commitment(first.id(), first.family(), cleanup_commitment(first, 3)?)?;
    plan.add_cleanup_commitment(second.id(), second.family(), cleanup_commitment(second, 4)?)?;

    // The lower and upper transmit boundaries are both valid observations
    for interval in [(15, 21), (10, 15)] {
        let mut session = AssessmentSession::new(&plan, super::support::budget_timebase()?);
        advance_to_armed(&mut session, &plan)?;
        session.record_stimulus(
            StimulusReceipt::new(RUN, stimulus.id(), tx(stimulus)?, packet_ref(0xa1, 1)?)?,
            super::support::budget_time(4)?,
        )?;
        let window = ObservationWindowReceipt::new(
            RUN,
            stimulus.sequence(),
            agent(1)?,
            endpoint_interface(1)?,
            window_timing(stimulus.sequence(), interval, (11, 15, 17))?,
            0,
            true,
        )?;
        session.record_transition(
            NeighborTransitionReceipt::new(
                RUN,
                stimulus.id(),
                AddressFamily::Ipv4,
                NeighborDisposition::ConflictRejected,
                window,
            )?,
            super::support::budget_time(5)?,
        )?;
    }

    // Neighbor checks cannot accept an IPv6 transition for the IPv4 endpoint
    let mut wrong_family = AssessmentSession::new(&plan, super::support::budget_timebase()?);
    advance_to_armed(&mut wrong_family, &plan)?;
    wrong_family.record_stimulus(
        StimulusReceipt::new(RUN, stimulus.id(), tx(stimulus)?, packet_ref(0xa1, 1)?)?,
        super::support::budget_time(4)?,
    )?;
    let wrong_window = ObservationWindowReceipt::new(
        RUN,
        stimulus.sequence(),
        agent(1)?,
        endpoint_interface(1)?,
        window_timing(stimulus.sequence(), (10, 21), (11, 15, 17))?,
        0,
        true,
    )?;
    assert!(
        wrong_family
            .record_transition(
                NeighborTransitionReceipt::new(
                    RUN,
                    stimulus.id(),
                    AddressFamily::Ipv6,
                    NeighborDisposition::ConflictRejected,
                    wrong_window,
                )?,
                super::support::budget_time(5)?
            )
            .is_err()
    );
    Ok(())
}

fn transition_receipt_with_binding(
    stimulus: Stimulus,
    disposition: NeighborDisposition,
    observed: Option<NeighborBinding>,
) -> Result<NeighborTransitionReceipt, Box<dyn Error>> {
    let window = ObservationWindowReceipt::new(
        RUN,
        stimulus.sequence(),
        agent(1)?,
        endpoint_interface(1)?,
        window_timing(stimulus.sequence(), (10, 21), (11, 15, 17))?,
        0,
        true,
    )?;
    let receipt = NeighborTransitionReceipt::new(
        RUN,
        stimulus.id(),
        AddressFamily::Ipv4,
        disposition,
        window,
    )?;
    Ok(observed.map_or(receipt, |binding| receipt.with_observed_binding(binding)))
}

#[track_caller]
fn assert_transition_rejected_without_state_change(
    session: &mut AssessmentSession,
    receipt: &NeighborTransitionReceipt,
) -> Result<(), Box<dyn Error>> {
    assert!(
        session
            .record_transition(*receipt, super::support::budget_time(5)?)
            .is_err()
    );
    assert_eq!(
        session.phase(),
        l2_onpath::AssessmentPhase::StimuliCommitted
    );
    Ok(())
}

#[test]
fn transition_binding_disposition_session_state() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let original = scenario
        .plan
        .endpoints()
        .first()
        .ok_or("missing endpoint")?
        .binding();
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_armed(&mut session, &scenario.plan)?;
    session.record_stimulus(
        StimulusReceipt::new(
            RUN,
            scenario.stimulus.id(),
            tx(scenario.stimulus)?,
            packet_ref(0xa1, 1)?,
        )?,
        super::support::budget_time(4)?,
    )?;

    let changed = NeighborBinding::new(
        original.endpoint(),
        original.address(),
        MacAddress::new([0x02, 0, 0, 0, 0, 0xaa])?,
    )?;

    // Disposition and attached binding evidence must agree with the stimulus
    for (disposition, observed) in [
        (NeighborDisposition::ConflictAccepted, None),
        (NeighborDisposition::Stable, Some(changed)),
        (NeighborDisposition::UnsolicitedAdvertisementAccepted, None),
    ] {
        let receipt = transition_receipt_with_binding(scenario.stimulus, disposition, observed)?;
        assert_transition_rejected_without_state_change(&mut session, &receipt)?;
    }

    // Endpoint identity, address family, and original address are all bound
    let unrelated_endpoint = NeighborBinding::new(
        agent(2)?,
        original.address(),
        MacAddress::new([0x02, 0, 0, 0, 0, 0xab])?,
    )?;
    let unrelated_family = NeighborBinding::new(
        original.endpoint(),
        "2001:db8::10".parse()?,
        MacAddress::new([0x02, 0, 0, 0, 0, 0xac])?,
    )?;
    let unrelated_address = NeighborBinding::new(
        original.endpoint(),
        "192.0.2.99".parse()?,
        MacAddress::new([0x02, 0, 0, 0, 0, 0xad])?,
    )?;
    for observed in [unrelated_endpoint, unrelated_family, unrelated_address] {
        let receipt = transition_receipt_with_binding(
            scenario.stimulus,
            NeighborDisposition::ConflictAccepted,
            Some(observed),
        )?;
        assert_transition_rejected_without_state_change(&mut session, &receipt)?;
    }

    // A changed binding with its exact accepted ARP disposition is valid
    assert!(
        session
            .record_transition(
                transition_receipt_with_binding(
                    scenario.stimulus,
                    NeighborDisposition::ConflictAccepted,
                    Some(changed),
                )?,
                super::support::budget_time(5)?
            )
            .is_ok()
    );
    assert_eq!(
        session.phase(),
        l2_onpath::AssessmentPhase::TransitionsRecorded
    );
    Ok(())
}
