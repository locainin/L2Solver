use std::error::Error;

use l2_canary::{AgentKey, MIN_KEY_LEN, SessionKey, encode};
use l2_helper_protocol::InterfaceBindingRequest;
use l2_segmentation::{
    Agent, AgentId, ClockDomainId, ClockStamp, ControllerEvent, DirectedRule, EvaluationContext,
    EvaluationStatus, Evaluator, ObservationWindowReceipt, ObservationWindowTiming, PlanInput,
    PlannedCanaryFrame, Probe, RuleExpectation, SegmentId, TxCommitment, TxReceipt, TxTiming,
};

const RUN: [u8; 16] = [0x71; 16];
const OTHER_RUN: [u8; 16] = [0x74; 16];
const SOURCE: [u8; 16] = [0x72; 16];
const DESTINATION: [u8; 16] = [0x73; 16];

const fn interface(
    ifindex: u32,
) -> Result<InterfaceBindingRequest, l2_helper_protocol::ProtocolError> {
    InterfaceBindingRequest::new(1, 2, ifindex, 1)
}

fn deny_plan() -> Result<l2_segmentation::Plan, Box<dyn Error>> {
    let mut input = PlanInput::for_replay(RUN)?;
    input.segments = vec![SegmentId::new(1), SegmentId::new(2)];
    input.agents = vec![
        Agent::new(AgentId::new(SOURCE)?, SegmentId::new(1), interface(7)?),
        Agent::new(AgentId::new(DESTINATION)?, SegmentId::new(2), interface(8)?),
    ];
    input.rules = vec![DirectedRule::new(
        SegmentId::new(1),
        SegmentId::new(2),
        RuleExpectation::Deny,
        1,
    )];
    Ok(input.plan()?)
}

fn tx_timing(
    domain: [u8; 16],
    ticks: u64,
    committed_event: u64,
) -> Result<TxTiming, l2_segmentation::ReceiptError> {
    Ok(TxTiming::new(
        ClockStamp::new(ClockDomainId::new(domain)?, ticks)?,
        ControllerEvent::new(RUN, 1, committed_event)?,
    ))
}

fn window_timing(
    domain: [u8; 16],
    armed: u64,
    closed: u64,
    arm_ack: u64,
    close_issued: u64,
    complete: u64,
) -> Result<ObservationWindowTiming, l2_segmentation::ReceiptError> {
    ObservationWindowTiming::new(
        ClockStamp::new(ClockDomainId::new(domain)?, armed)?,
        ClockStamp::new(ClockDomainId::new(domain)?, closed)?,
        ControllerEvent::new(RUN, 1, arm_ack)?,
        ControllerEvent::new(RUN, 1, close_issued)?,
        ControllerEvent::new(RUN, 1, complete)?,
    )
}

fn planned_commitment(
    probe: &Probe,
    binding: InterfaceBindingRequest,
) -> Result<TxCommitment, Box<dyn Error>> {
    let canary = probe.canary()?;
    let agent_key = AgentKey::new(canary.source_agent_id(), &[0x45; MIN_KEY_LEN])?;
    let key = SessionKey::derive(&agent_key, &canary.identity())?;
    let payload = encode(&canary, &key)?;
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&l2_canary::ETHER_TYPE.to_be_bytes());
    frame.extend_from_slice(&payload);
    let planned = PlannedCanaryFrame::from_probe(*probe, &key, &frame)?;
    Ok(TxCommitment::from_planned_frame(&planned, binding))
}

fn record_absence(
    evaluator: &mut Evaluator,
    plan: &l2_segmentation::Plan,
    tx_timing: TxTiming,
    window_timing: ObservationWindowTiming,
) -> Result<(), Box<dyn Error>> {
    let probe = plan.probes().first().ok_or("missing probe")?;
    let binding = interface(7)?;
    let commitment = planned_commitment(probe, binding)?;
    let hash = commitment.frame_hash();
    evaluator.record_commitment(commitment)?;
    evaluator.record_tx(TxReceipt::new(
        RUN,
        probe.sequence(),
        binding,
        hash,
        tx_timing,
    )?)?;
    evaluator.record_window(ObservationWindowReceipt::new(
        RUN,
        probe.sequence(),
        AgentId::new(DESTINATION)?,
        interface(8)?,
        window_timing,
        0,
        true,
    )?)?;
    Ok(())
}

#[test]
fn causal_works_local_clock_domains() -> Result<(), Box<dyn Error>> {
    let plan = deny_plan()?;
    let mut evaluator = Evaluator::new(&plan);
    record_absence(
        &mut evaluator,
        &plan,
        tx_timing([11; 16], 9, 3)?,
        window_timing([22; 16], 100, 200, 1, 5, 7)?,
    )?;

    assert_eq!(
        evaluator
            .evaluate(&EvaluationContext::healthy())
            .results()
            .first()
            .ok_or("missing result")?
            .status(),
        EvaluationStatus::Pass
    );
    Ok(())
}

#[test]
fn overlapping_local_not_controller_causality() -> Result<(), Box<dyn Error>> {
    let plan = deny_plan()?;
    let mut evaluator = Evaluator::new(&plan);
    record_absence(
        &mut evaluator,
        &plan,
        tx_timing([11; 16], 150, 8)?,
        window_timing([22; 16], 100, 200, 1, 5, 7)?,
    )?;

    assert_eq!(
        evaluator
            .evaluate(&EvaluationContext::healthy())
            .results()
            .first()
            .ok_or("missing result")?
            .status(),
        EvaluationStatus::Inconclusive
    );
    Ok(())
}

#[test]
fn window_local_stamps_share_domain() -> Result<(), Box<dyn Error>> {
    assert!(ClockDomainId::new([0; 16]).is_err());
    assert!(ClockStamp::new(ClockDomainId::new([1; 16])?, 0).is_err());
    assert!(ControllerEvent::new([0; 16], 1, 1).is_err());
    assert!(ControllerEvent::new(RUN, 0, 1).is_err());
    assert!(ControllerEvent::new(RUN, 1, 0).is_err());
    assert!(
        ObservationWindowTiming::new(
            ClockStamp::new(ClockDomainId::new([11; 16])?, 10)?,
            ClockStamp::new(ClockDomainId::new([22; 16])?, 20)?,
            ControllerEvent::new(RUN, 1, 1)?,
            ControllerEvent::new(RUN, 1, 2)?,
            ControllerEvent::new(RUN, 1, 3)?,
        )
        .is_err()
    );
    assert!(window_timing([11; 16], 20, 10, 1, 2, 3).is_err());
    Ok(())
}

#[test]
fn controller_events_strictly_ordered() {
    assert!(window_timing([11; 16], 10, 20, 2, 2, 3).is_err());
    assert!(window_timing([11; 16], 10, 20, 3, 2, 4).is_err());
    assert!(window_timing([11; 16], 10, 20, 1, 3, 2).is_err());
}

#[test]
fn controller_event_run_identity() -> Result<(), Box<dyn Error>> {
    assert!(
        ObservationWindowTiming::new(
            ClockStamp::new(ClockDomainId::new([0x11; 16])?, 10)?,
            ClockStamp::new(ClockDomainId::new([0x11; 16])?, 20)?,
            ControllerEvent::new(RUN, 1, 1)?,
            ControllerEvent::new(OTHER_RUN, 1, 5)?,
            ControllerEvent::new(RUN, 1, 7)?,
        )
        .is_err()
    );
    let transmit_timing = TxTiming::new(
        ClockStamp::new(ClockDomainId::new([0x11; 16])?, 10)?,
        ControllerEvent::new(OTHER_RUN, 1, 3)?,
    );
    assert!(TxReceipt::new(RUN, 1, interface(7)?, [0x91; 32], transmit_timing).is_err());
    let window_timing = ObservationWindowTiming::new(
        ClockStamp::new(ClockDomainId::new([0x11; 16])?, 10)?,
        ClockStamp::new(ClockDomainId::new([0x11; 16])?, 20)?,
        ControllerEvent::new(OTHER_RUN, 1, 1)?,
        ControllerEvent::new(OTHER_RUN, 1, 5)?,
        ControllerEvent::new(OTHER_RUN, 1, 7)?,
    )?;
    assert!(
        ObservationWindowReceipt::new(
            RUN,
            1,
            AgentId::new(DESTINATION)?,
            interface(8)?,
            window_timing,
            0,
            true,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn transmit_event_name_receipt_sequence() -> Result<(), Box<dyn Error>> {
    let timing = TxTiming::new(
        ClockStamp::new(ClockDomainId::new([0x31; 16])?, 10)?,
        ControllerEvent::new(RUN, 1, 3)?,
    );

    assert_eq!(
        TxReceipt::new(RUN, 2, interface(7)?, [0x41; 32], timing),
        Err(l2_segmentation::ReceiptError::ControllerSequenceMismatch)
    );
    Ok(())
}

#[test]
fn window_receipt_sequence() -> Result<(), Box<dyn Error>> {
    let domain = ClockDomainId::new([0x32; 16])?;
    assert_eq!(
        ObservationWindowTiming::new(
            ClockStamp::new(domain, 10)?,
            ClockStamp::new(domain, 20)?,
            ControllerEvent::new(RUN, 1, 1)?,
            ControllerEvent::new(RUN, 2, 5)?,
            ControllerEvent::new(RUN, 1, 7)?,
        ),
        Err(l2_segmentation::ReceiptError::ControllerSequenceMismatch)
    );

    let timing = ObservationWindowTiming::new(
        ClockStamp::new(domain, 10)?,
        ClockStamp::new(domain, 20)?,
        ControllerEvent::new(RUN, 1, 1)?,
        ControllerEvent::new(RUN, 1, 5)?,
        ControllerEvent::new(RUN, 1, 7)?,
    )?;
    assert_eq!(
        ObservationWindowReceipt::new(
            RUN,
            2,
            AgentId::new(DESTINATION)?,
            interface(8)?,
            timing,
            0,
            true,
        ),
        Err(l2_segmentation::ReceiptError::ControllerSequenceMismatch)
    );
    Ok(())
}

#[test]
fn transmit_interface_match_commitment() -> Result<(), Box<dyn Error>> {
    let plan = deny_plan()?;
    let probe = plan.probes().first().ok_or("missing probe")?;
    let mut evaluator = Evaluator::new(&plan);
    let commitment = planned_commitment(probe, interface(7)?)?;
    let hash = commitment.frame_hash();
    evaluator.record_commitment(commitment)?;

    assert_eq!(
        evaluator.record_tx(TxReceipt::new(
            RUN,
            probe.sequence(),
            interface(8)?,
            hash,
            tx_timing([11; 16], 9, 3)?,
        )?),
        Err(l2_segmentation::ReceiptError::InterfaceMismatch)
    );
    Ok(())
}
