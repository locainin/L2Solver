use std::error::Error;

use l2_onpath::{
    ArmReceipt, AssessmentPhase, AssessmentPlan, AssessmentSession, CheckKind, CleanupReceipt,
    ClockDomainId, ClockStamp, EvidenceOrigin, OriginalBindingReceipt, PrecheckReceipt,
    SessionError, Stimulus, StimulusReceipt,
};
use l2_segmentation::{ControllerEvent, TxCommitment, TxReceipt, TxTiming};

use super::support::{
    RUN, advance_to_armed, budget_time, budget_timebase, cleanup_commitment, cleanup_tx, endpoint,
    ethernet_frame, packet_ref, stimulus_commitment, transmit_interface,
};

const LONG_STIMULUS_COUNT: u64 = 255;

fn unique_tx(stimulus: Stimulus) -> Result<TxReceipt, Box<dyn Error>> {
    let sequence = stimulus.sequence();
    let commitment = stimulus_commitment(sequence)?;
    let event_ordinal = sequence.checked_add(100).ok_or("event ordinal overflow")?;
    Ok(TxReceipt::new(
        RUN,
        sequence,
        transmit_interface()?,
        commitment.frame_hash(),
        TxTiming::new(
            ClockStamp::new(ClockDomainId::new([11; 16])?, sequence)?,
            ControllerEvent::new(RUN, sequence, event_ordinal)?,
        ),
    )?)
}

fn packet_limited_plan() -> Result<(AssessmentPlan, Vec<Stimulus>), Box<dyn Error>> {
    let first = endpoint(1, 10)?;
    let second = endpoint(2, 20)?;
    let mut plan = AssessmentPlan::for_replay(RUN)?;
    plan.add_endpoint(first)?;
    plan.add_endpoint(second)?;
    plan.add_check(CheckKind::ArpSpoofSusceptibility)?;
    let mut stimuli = Vec::new();
    for sequence in 1..=LONG_STIMULUS_COUNT {
        let stimulus = Stimulus::new(
            u16::try_from(sequence)?,
            CheckKind::ArpSpoofSusceptibility,
            first.id(),
            sequence,
        )?;
        plan.add_stimulus(stimulus)?;
        plan.add_commitment(stimulus_commitment(sequence)?)?;
        stimuli.push(stimulus);
    }
    plan.add_cleanup_commitment(first.id(), first.family(), cleanup_commitment(first, 300)?)?;
    plan.add_cleanup_commitment(
        second.id(),
        second.family(),
        cleanup_commitment(second, 301)?,
    )?;
    Ok((plan, stimuli))
}

fn oversized_cleanup_plan() -> Result<AssessmentPlan, Box<dyn Error>> {
    let endpoints = [endpoint(1, 10)?, endpoint(2, 20)?, endpoint(3, 30)?];
    let mut plan = AssessmentPlan::for_replay(RUN)?;
    for endpoint in endpoints {
        plan.add_endpoint(endpoint)?;
    }
    plan.add_check(CheckKind::ArpSpoofSusceptibility)?;
    let payload = vec![0; 65_521];
    let frame = ethernet_frame(0x0806, &payload, 0x70);
    for (ordinal, endpoint) in endpoints.iter().enumerate() {
        let sequence = u64::try_from(ordinal + 1)?;
        let commitment =
            TxCommitment::from_frame_claim(RUN, sequence, endpoint.interface(), &frame)?;
        plan.add_cleanup_commitment(endpoint.id(), endpoint.family(), commitment)?;
    }
    Ok(plan)
}

fn record_stimulus(
    session: &mut AssessmentSession,
    stimulus: Stimulus,
) -> Result<(), Box<dyn Error>> {
    session.record_stimulus(
        StimulusReceipt::new(
            RUN,
            stimulus.id(),
            unique_tx(stimulus)?,
            packet_ref(0xa1, stimulus.sequence())?,
        )?,
        budget_time(4)?,
    )?;
    Ok(())
}

#[test]
fn experiment_transmits_cannot_cleanup_packets() -> Result<(), Box<dyn Error>> {
    let (plan, stimuli) = packet_limited_plan()?;
    let mut session = AssessmentSession::new(&plan, budget_timebase()?);
    advance_to_armed(&mut session, &plan)?;
    for stimulus in stimuli.iter().take(254) {
        record_stimulus(&mut session, *stimulus)?;
    }
    let last = stimuli.get(254).copied().ok_or("missing final stimulus")?;
    let error = session.record_stimulus(
        StimulusReceipt::new(
            RUN,
            last.id(),
            unique_tx(last)?,
            packet_ref(0xa1, last.sequence())?,
        )?,
        budget_time(4)?,
    );
    assert!(matches!(
        error,
        Err(SessionError::ResourceBudgetExceeded {
            packets: 257,
            packet_limit: 256,
            ..
        })
    ));
    let result = session.evaluate();
    let usage = result
        .results()
        .first()
        .ok_or("missing check result")?
        .budget_usage();
    assert_eq!(usage.packets_used(), 254);
    assert_eq!(usage.cleanup_packets_reserved(), 2);
    assert_eq!(session.phase(), AssessmentPhase::EndpointsArmed);
    Ok(())
}

#[test]
fn precheck_cleanup_exceeds_byte_budget() -> Result<(), Box<dyn Error>> {
    let plan = oversized_cleanup_plan()?;
    let mut session = AssessmentSession::new(&plan, budget_timebase()?);
    let receipt = PrecheckReceipt::complete_for_endpoints(RUN, 3)?;
    let error = session.record_precheck(receipt, budget_time(1)?);
    assert!(matches!(
        error,
        Err(SessionError::ResourceBudgetExceeded {
            packets: 3,
            bytes: 196_605,
            byte_limit: 65_536,
            ..
        })
    ));
    assert_eq!(session.phase(), AssessmentPhase::Created);
    Ok(())
}

#[test]
fn receipt_clock_not_advance_state() -> Result<(), Box<dyn Error>> {
    let first = endpoint(1, 10)?;
    let mut plan = AssessmentPlan::for_replay(RUN)?;
    plan.add_endpoint(first)?;
    plan.add_check(CheckKind::ArpSpoofSusceptibility)?;
    plan.add_cleanup_commitment(first.id(), first.family(), cleanup_commitment(first, 2)?)?;
    let mut session = AssessmentSession::new(&plan, budget_timebase()?);
    session.record_precheck(
        PrecheckReceipt::complete_for_endpoints(RUN, 1)?,
        budget_time(1)?,
    )?;

    let original = OriginalBindingReceipt::new(
        RUN,
        first.binding(),
        first.interface(),
        EvidenceOrigin::Packet(packet_ref(0x22, 1)?),
    )?;
    let other_clock = ClockStamp::new(ClockDomainId::new([0x78; 16])?, 2)?;
    assert!(matches!(
        session.record_original_binding(original, other_clock),
        Err(SessionError::ReceiptClockDomainMismatch { .. })
    ));
    assert_eq!(session.phase(), AssessmentPhase::Precheck);
    session.record_original_binding(original, budget_time(2)?)?;

    let arm = ArmReceipt::new(RUN, first.id(), first.family(), first.interface())?;
    assert!(matches!(
        session.arm_endpoint(arm, budget_time(1)?),
        Err(SessionError::ReceiptClockMovedBackwards { .. })
    ));
    assert_eq!(session.phase(), AssessmentPhase::OriginalBindingRecorded);
    session.arm_endpoint(arm, budget_time(3)?)?;
    assert_eq!(session.phase(), AssessmentPhase::EndpointsArmed);
    Ok(())
}

#[test]
fn deadline_experiment_reserved_cleanup() -> Result<(), Box<dyn Error>> {
    let scenario = super::support::Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, budget_timebase()?);
    advance_to_armed(&mut session, &scenario.plan)?;
    let stimulus = scenario.stimulus;
    assert!(matches!(
        session.record_stimulus(
            StimulusReceipt::new(
                RUN,
                stimulus.id(),
                unique_tx(stimulus)?,
                packet_ref(0xa1, stimulus.sequence())?,
            )?,
            budget_time(30_002)?
        ),
        Err(SessionError::DurationBudgetExceeded { .. })
    ));
    assert_eq!(session.phase(), AssessmentPhase::EndpointsArmed);
    assert_eq!(
        session
            .budget_usage(CheckKind::ArpSpoofSusceptibility)
            .packets_used(),
        0
    );

    for (ordinal, endpoint) in scenario.plan.endpoints().iter().enumerate() {
        let sequence = u64::try_from(ordinal + 3)?;
        session.record_cleanup(
            &CleanupReceipt::new(
                RUN,
                endpoint.interface(),
                endpoint.binding(),
                true,
                cleanup_tx(*endpoint, sequence)?,
                packet_ref(0xc1, u64::try_from(ordinal + 1)?)?,
            )?,
            budget_time(30_002)?,
        )?;
        if ordinal == 0 {
            let rejected = session.record_stimulus(
                StimulusReceipt::new(
                    RUN,
                    stimulus.id(),
                    unique_tx(stimulus)?,
                    packet_ref(0xa1, stimulus.sequence())?,
                )?,
                budget_time(30_003)?,
            );
            assert!(matches!(
                rejected,
                Err(SessionError::WrongPhase {
                    phase: AssessmentPhase::CleanupInProgress,
                    ..
                })
            ));
        }
    }
    assert_eq!(session.phase(), AssessmentPhase::CleanupRecorded);
    let usage = session
        .evaluate()
        .results()
        .first()
        .ok_or("missing check result")?
        .budget_usage();
    assert_eq!(usage.elapsed_millis(), Some(30_001));
    assert_eq!(usage.packets_used(), 0);
    Ok(())
}
