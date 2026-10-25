use std::error::Error;

use l2_onpath::{
    AssessmentSession, AuthenticatedCanaryReceipt, CanaryArrivalReceipt, CanaryWireEvidence,
    ClockDomainId, ClockStamp, ControllerEvent, NeighborDisposition, ObservationWindowReceipt,
    ObservationWindowTiming, ReceiptError, SessionError, StimulusReceipt, TxTiming,
};
use l2_segmentation::TxReceipt;

use super::support::{
    RUN, Scenario, advance_to_transitions, agent, canary_for, observed_at, packet_ref,
    receiver_interface, transmit_interface, tx_timing, window_timing,
};

#[test]
fn invalid_authentication_is_rejected() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_transitions(
        &mut session,
        &scenario.plan,
        scenario.stimulus,
        NeighborDisposition::ConflictRejected,
    )?;
    let canary = canary_for(&scenario.plan)?;
    let mut wire = canary.wire.clone();
    let Some(last) = wire.last_mut() else {
        return Err("encoded canary was unexpectedly empty".into());
    };
    *last ^= 1;

    // Keep the altered bytes at the public wire boundary under test
    assert!(
        session
            .record_canary_wire(
                &wire,
                &canary.key,
                CanaryWireEvidence::new(
                    canary.tx()?,
                    canary.window(0, true)?,
                    receiver_interface()?,
                    observed_at(27)?,
                    packet_ref(0xb1, 1)?,
                ),
                super::support::budget_time(6)?
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn blocked_canary_requires_clean_coverage() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_transitions(
        &mut session,
        &scenario.plan,
        scenario.stimulus,
        NeighborDisposition::ConflictRejected,
    )?;
    let canary = canary_for(&scenario.plan)?;

    // Loss or an unfinished window cannot prove that a blocked canary stayed absent
    assert!(
        session
            .record_blocked_canary_wire(
                &canary.wire,
                &canary.key,
                canary.tx()?,
                canary.window(1, true)?,
                packet_ref(0xb1, 1)?,
                super::support::budget_time(6)?
            )
            .is_err()
    );
    assert!(
        session
            .record_blocked_canary_wire(
                &canary.wire,
                &canary.key,
                canary.tx()?,
                canary.window(0, false)?,
                packet_ref(0xb1, 1)?,
                super::support::budget_time(6)?
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn canary_window_covers_its_transmit() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let canary = canary_for(&scenario.plan)?;

    // Windows ending before or starting after the send cannot carry its evidence
    for interval in [(28, 30), (25, 26)] {
        let mut session =
            AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
        advance_to_transitions(
            &mut session,
            &scenario.plan,
            scenario.stimulus,
            NeighborDisposition::ConflictRejected,
        )?;
        assert!(
            session
                .record_blocked_canary_wire(
                    &canary.wire,
                    &canary.key,
                    canary.tx()?,
                    canary.window_at_events(interval, (4, 5, 7))?,
                    packet_ref(0xb1, 1)?,
                    super::support::budget_time(6)?
                )
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn arrived_canary_not_free_window() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    super::support::advance_to_transitions(
        &mut session,
        &scenario.plan,
        scenario.stimulus,
        NeighborDisposition::ConflictRejected,
    )?;
    let canary = canary_for(&scenario.plan)?;

    assert!(matches!(
        session.record_canary_wire(
            &canary.wire,
            &canary.key,
            CanaryWireEvidence::new(
                canary.tx()?,
                canary.window_at_events((28, 30), (4, 5, 7))?,
                receiver_interface()?,
                observed_at(29)?,
                packet_ref(0xb1, 1)?,
            ),
            super::support::budget_time(6)?
        ),
        Err(SessionError::Model(
            l2_onpath::ModelError::CausalCoverageMissing
        ))
    ));
    assert_eq!(
        session.phase(),
        l2_onpath::AssessmentPhase::TransitionsRecorded
    );

    // A directly observed packet does not depend on absence-quality evidence
    session.record_canary_wire(
        &canary.wire,
        &canary.key,
        CanaryWireEvidence::new(
            canary.tx()?,
            canary.window(1, false)?,
            receiver_interface()?,
            observed_at(27)?,
            packet_ref(0xb1, 1)?,
        ),
        super::support::budget_time(6)?,
    )?;
    assert_eq!(
        session.phase(),
        l2_onpath::AssessmentPhase::CanariesRecorded
    );
    Ok(())
}

#[test]
fn wrong_receiver_rejected_without_mutation() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_transitions(
        &mut session,
        &scenario.plan,
        scenario.stimulus,
        NeighborDisposition::ConflictRejected,
    )?;
    let canary = canary_for(&scenario.plan)?;
    let source_window = ObservationWindowReceipt::new(
        RUN,
        canary.canary.sequence(),
        agent(1)?,
        receiver_interface()?,
        window_timing(canary.canary.sequence(), (25, 30), (21, 25, 27))?,
        0,
        true,
    )?;

    assert!(matches!(
        session.record_canary_wire(
            &canary.wire,
            &canary.key,
            CanaryWireEvidence::new(
                canary.tx()?,
                source_window,
                receiver_interface()?,
                observed_at(27)?,
                packet_ref(0xb1, 1)?,
            ),
            super::support::budget_time(6)?
        ),
        Err(SessionError::Segmentation(
            l2_segmentation::ReceiptError::WrongReceiver
        ))
    ));

    assert_eq!(
        session.phase(),
        l2_onpath::AssessmentPhase::TransitionsRecorded
    );
    Ok(())
}

#[test]
fn interface_mismatches_rejected_without_mutation() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_transitions(
        &mut session,
        &scenario.plan,
        scenario.stimulus,
        NeighborDisposition::ConflictRejected,
    )?;
    let canary = canary_for(&scenario.plan)?;
    assert!(matches!(
        session.record_canary_wire(
            &canary.wire,
            &canary.key,
            CanaryWireEvidence::new(
                canary.tx()?,
                canary.window(0, true)?,
                transmit_interface()?,
                observed_at(27)?,
                packet_ref(0xb1, 1)?,
            ),
            super::support::budget_time(6)?
        ),
        Err(SessionError::Segmentation(
            l2_segmentation::ReceiptError::ObservationInterfaceMismatch
        ))
    ));
    let unrelated_interface = l2_onpath::InterfaceBindingRequest::new(1, 2, 99, 1)?;
    let unrelated_window = ObservationWindowReceipt::new(
        RUN,
        canary.canary.sequence(),
        agent(2)?,
        unrelated_interface,
        window_timing(canary.canary.sequence(), (25, 30), (21, 25, 27))?,
        0,
        true,
    )?;
    assert!(matches!(
        session.record_canary_wire(
            &canary.wire,
            &canary.key,
            CanaryWireEvidence::new(
                canary.tx()?,
                unrelated_window,
                unrelated_interface,
                observed_at(27)?,
                packet_ref(0xb1, 1)?,
            ),
            super::support::budget_time(6)?
        ),
        Err(SessionError::Receipt(
            ReceiptError::ObservationInterfaceMismatch
        ))
    ));
    assert_eq!(
        session.phase(),
        l2_onpath::AssessmentPhase::TransitionsRecorded
    );
    Ok(())
}

#[test]
fn canary_transmit_rejects_scope_mismatches() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let canary = canary_for(&scenario.plan)?;
    let window = canary.window_at((26, 28))?;
    let request = l2_onpath::InterfaceBindingRequest::new(1, 2, 3, 1)?;
    let verified = l2_canary::verify(l2_canary::UnverifiedCanary::new(&canary.wire), &canary.key)?;
    let arrival = CanaryArrivalReceipt::from_verified(
        verified,
        window,
        receiver_interface()?,
        observed_at(27)?,
        packet_ref(0xb1, 1)?,
    )?;

    // The transmit run and sequence must match the authenticated canary
    let wrong_run = TxReceipt::new(
        [8; l2_onpath::ID_LEN],
        canary.canary.sequence(),
        request,
        [6; 32],
        TxTiming::new(
            ClockStamp::new(ClockDomainId::new([11; 16])?, 27)?,
            ControllerEvent::new([8; l2_onpath::ID_LEN], canary.canary.sequence(), 23)?,
        ),
    )?;
    assert!(AuthenticatedCanaryReceipt::from_arrival(arrival, wrong_run).is_err());
    let wrong_sequence = TxReceipt::new(RUN, 3, request, [6; 32], tx_timing(3, 27, 33)?)?;
    assert!(AuthenticatedCanaryReceipt::from_arrival(arrival, wrong_sequence).is_err());
    Ok(())
}

#[test]
fn canary_arrival_rejects_scope_mismatches() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let canary = canary_for(&scenario.plan)?;
    let verified = l2_canary::verify(l2_canary::UnverifiedCanary::new(&canary.wire), &canary.key)?;

    // The observation window carries the same run, sequence, and receiver scope
    let wrong_window_run = ObservationWindowReceipt::new(
        [8; l2_onpath::ID_LEN],
        canary.canary.sequence(),
        agent(2)?,
        receiver_interface()?,
        ObservationWindowTiming::new(
            ClockStamp::new(ClockDomainId::new([22; 16])?, 26)?,
            ClockStamp::new(ClockDomainId::new([22; 16])?, 28)?,
            ControllerEvent::new([8; l2_onpath::ID_LEN], canary.canary.sequence(), 21)?,
            ControllerEvent::new([8; l2_onpath::ID_LEN], canary.canary.sequence(), 25)?,
            ControllerEvent::new([8; l2_onpath::ID_LEN], canary.canary.sequence(), 27)?,
        )?,
        0,
        true,
    )?;
    assert!(
        CanaryArrivalReceipt::from_verified(
            verified,
            wrong_window_run,
            receiver_interface()?,
            observed_at(27)?,
            packet_ref(0xb1, 1)?,
        )
        .is_err()
    );
    let wrong_window_sequence = ObservationWindowReceipt::new(
        RUN,
        canary.canary.sequence() + 1,
        agent(2)?,
        receiver_interface()?,
        window_timing(canary.canary.sequence() + 1, (26, 28), (31, 35, 37))?,
        0,
        true,
    )?;
    assert!(
        CanaryArrivalReceipt::from_verified(
            verified,
            wrong_window_sequence,
            receiver_interface()?,
            observed_at(27)?,
            packet_ref(0xb1, 1)?,
        )
        .is_err()
    );
    let wrong_receiver = ObservationWindowReceipt::new(
        RUN,
        canary.canary.sequence(),
        agent(1)?,
        receiver_interface()?,
        window_timing(canary.canary.sequence(), (26, 28), (21, 25, 27))?,
        0,
        true,
    )?;
    assert!(
        CanaryArrivalReceipt::from_verified(
            verified,
            wrong_receiver,
            receiver_interface()?,
            observed_at(27)?,
            packet_ref(0xb1, 1)?,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn stimulus_receipt_requires_matching_commitment() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    super::support::advance_to_armed(&mut session, &scenario.plan)?;
    let wrong = TxReceipt::new(
        RUN,
        scenario.stimulus.sequence(),
        l2_onpath::InterfaceBindingRequest::new(1, 2, 3, 1)?,
        [8; 32],
        tx_timing(scenario.stimulus.sequence(), 15, 13)?,
    )?;

    assert!(matches!(
        session.record_stimulus(
            StimulusReceipt::new(RUN, scenario.stimulus.id(), wrong, packet_ref(0xa1, 1)?,)?,
            super::support::budget_time(4)?
        ),
        Err(SessionError::Receipt(ReceiptError::CommitmentMismatch {
            sequence: 1,
        }))
    ));
    Ok(())
}

#[test]
fn stimulus_receipt_matching_interface_commitment() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    super::support::advance_to_armed(&mut session, &scenario.plan)?;
    let wrong = TxReceipt::new(
        RUN,
        scenario.stimulus.sequence(),
        l2_onpath::InterfaceBindingRequest::new(1, 2, 4, 1)?,
        scenario
            .plan
            .commitment(scenario.stimulus.sequence())
            .ok_or("missing stimulus commitment")?
            .frame_hash(),
        tx_timing(scenario.stimulus.sequence(), 15, 13)?,
    )?;

    assert!(matches!(
        session.record_stimulus(
            StimulusReceipt::new(RUN, scenario.stimulus.id(), wrong, packet_ref(0xa1, 1)?,)?,
            super::support::budget_time(4)?
        ),
        Err(SessionError::Receipt(ReceiptError::InterfaceMismatch {
            sequence: 1,
        }))
    ));
    assert_eq!(session.phase(), l2_onpath::AssessmentPhase::EndpointsArmed);
    Ok(())
}

#[test]
fn canary_receipt_requires_matching_commitment() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    super::support::advance_to_transitions(
        &mut session,
        &scenario.plan,
        scenario.stimulus,
        NeighborDisposition::ConflictRejected,
    )?;
    let canary = canary_for(&scenario.plan)?;
    let wrong = TxReceipt::new(
        RUN,
        canary.canary.sequence(),
        l2_onpath::InterfaceBindingRequest::new(1, 2, 3, 1)?,
        [9; 32],
        tx_timing(canary.canary.sequence(), 27, 23)?,
    )?;

    assert!(matches!(
        session.record_canary_wire(
            &canary.wire,
            &canary.key,
            CanaryWireEvidence::new(
                wrong,
                canary.window(0, true)?,
                receiver_interface()?,
                observed_at(27)?,
                packet_ref(0xb1, 1)?,
            ),
            super::support::budget_time(6)?
        ),
        Err(SessionError::Receipt(ReceiptError::CommitmentMismatch {
            sequence: 2,
        }))
    ));
    Ok(())
}

#[test]
fn canary_cannot_stimulus_controller_event() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_transitions(
        &mut session,
        &scenario.plan,
        scenario.stimulus,
        NeighborDisposition::ConflictRejected,
    )?;
    let canary = canary_for(&scenario.plan)?;
    let commitment = scenario
        .plan
        .commitment(canary.canary.sequence())
        .ok_or("missing canary commitment")?;
    let reused = TxReceipt::new(
        RUN,
        canary.canary.sequence(),
        commitment.interface(),
        commitment.frame_hash(),
        tx_timing(canary.canary.sequence(), 27, 13)?,
    )?;

    assert!(matches!(
        session.record_canary_wire(
            &canary.wire,
            &canary.key,
            CanaryWireEvidence::new(
                reused,
                canary.window_at_events((25, 30), (12, 25, 27))?,
                receiver_interface()?,
                observed_at(27)?,
                packet_ref(0xb1, 1)?,
            ),
            super::support::budget_time(6)?
        ),
        Err(SessionError::Segmentation(
            l2_segmentation::ReceiptError::ControllerEventReuse { ordinal: 13 }
        ))
    ));
    assert_eq!(
        session.phase(),
        l2_onpath::AssessmentPhase::TransitionsRecorded
    );
    session.record_canary_wire(
        &canary.wire,
        &canary.key,
        CanaryWireEvidence::new(
            canary.tx()?,
            canary.window(0, true)?,
            receiver_interface()?,
            observed_at(27)?,
            packet_ref(0xb1, 1)?,
        ),
        super::support::budget_time(6)?,
    )?;
    assert_eq!(
        session.phase(),
        l2_onpath::AssessmentPhase::CanariesRecorded
    );
    Ok(())
}

#[test]
fn missing_commitment_rejects_stimulus_receipt() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::without_commitments()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    super::support::advance_to_armed(&mut session, &scenario.plan)?;

    assert!(matches!(
        session.record_stimulus(
            StimulusReceipt::new(
                RUN,
                scenario.stimulus.id(),
                super::support::tx(scenario.stimulus)?,
                packet_ref(0xa1, 1)?,
            )?,
            super::support::budget_time(4)?
        ),
        Err(SessionError::Receipt(ReceiptError::MissingCommitment {
            sequence: 1,
        }))
    ));
    Ok(())
}

#[test]
fn missing_commitment_rejects_canary_receipt() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::without_canary_commitment()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    super::support::advance_to_transitions(
        &mut session,
        &scenario.plan,
        scenario.stimulus,
        NeighborDisposition::ConflictRejected,
    )?;
    let canary = canary_for(&scenario.plan)?;

    assert!(matches!(
        session.record_canary_wire(
            &canary.wire,
            &canary.key,
            CanaryWireEvidence::new(
                canary.tx()?,
                canary.window(0, true)?,
                receiver_interface()?,
                observed_at(27)?,
                packet_ref(0xb1, 1)?,
            ),
            super::support::budget_time(6)?
        ),
        Err(SessionError::Receipt(ReceiptError::MissingCommitment {
            sequence: 2,
        }))
    ));
    Ok(())
}
