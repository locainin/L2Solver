use std::error::Error;

use l2_canary::{ETHER_TYPE, encode};
use l2_helper_protocol::InterfaceBindingRequest;
use l2_segmentation::{
    ClockDomainId, ClockStamp, ControllerEvent, EvaluationContext, EvaluationStatus, Evaluator,
    ObservationWindowReceipt, ObservationWindowTiming, PlannedCanaryFrame, ReceiptError,
    RuleExpectation, TxCommitment, TxReceipt, TxTiming,
};

use super::support::{RUN, agent_interface, input_with_rule, key_for};

fn interface(ifindex: u32) -> Result<InterfaceBindingRequest, Box<dyn Error>> {
    Ok(InterfaceBindingRequest::new(1, 2, ifindex, 1)?)
}

fn ethernet_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&ETHER_TYPE.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn arbitrary_frame_cannot_canary_absence() -> Result<(), Box<dyn Error>> {
    let plan = l2_segmentation::plan(&input_with_rule(RuleExpectation::Deny, 1)?)?;
    let probe = *plan.probes().first().ok_or("missing probe")?;
    let unrelated_frame = ethernet_frame(&[0x55; 32]);
    let commitment =
        TxCommitment::from_frame_claim(RUN, probe.sequence(), interface(20)?, &unrelated_frame)?;
    let mut evaluator = Evaluator::new(&plan);

    assert_eq!(
        evaluator.record_commitment(commitment),
        Err(ReceiptError::CommitmentCanaryMismatch)
    );
    let status = evaluator
        .evaluate(&EvaluationContext::healthy())
        .results()
        .first()
        .map(l2_segmentation::RuleResult::status)
        .ok_or("missing rule result")?;
    assert_eq!(status, EvaluationStatus::Inconclusive);
    Ok(())
}

#[test]
fn planned_canary_wire_frame_receipt() -> Result<(), Box<dyn Error>> {
    let plan = l2_segmentation::plan(&input_with_rule(RuleExpectation::Deny, 1)?)?;
    let probe = *plan.probes().first().ok_or("missing probe")?;
    let canary = probe.canary()?;
    let key = key_for(&canary)?;
    let payload = encode(&canary, &key)?;
    let frame = ethernet_frame(&payload);
    let planned = PlannedCanaryFrame::from_probe(probe, &key, &frame)?;
    let sender_interface = agent_interface(1)?;
    let receiver_interface = agent_interface(2)?;
    let commitment = TxCommitment::from_planned_frame(&planned, sender_interface);
    assert_eq!(commitment.frame_length(), u64::try_from(frame.len())?);
    let transmit = TxReceipt::new(
        RUN,
        probe.sequence(),
        sender_interface,
        planned.frame_hash(),
        TxTiming::new(
            ClockStamp::new(ClockDomainId::new([0x31; 16])?, 150)?,
            ControllerEvent::new(RUN, probe.sequence(), 3)?,
        ),
    )?;
    let window = ObservationWindowReceipt::new(
        RUN,
        probe.sequence(),
        probe.destination_agent_id(),
        receiver_interface,
        ObservationWindowTiming::new(
            ClockStamp::new(ClockDomainId::new([0x32; 16])?, 100)?,
            ClockStamp::new(ClockDomainId::new([0x32; 16])?, 200)?,
            ControllerEvent::new(RUN, probe.sequence(), 1)?,
            ControllerEvent::new(RUN, probe.sequence(), 5)?,
            ControllerEvent::new(RUN, probe.sequence(), 7)?,
        )?,
        0,
        true,
    )?;
    let mut evaluator = Evaluator::new(&plan);

    evaluator.record_commitment(commitment)?;
    evaluator.record_tx(transmit)?;
    evaluator.record_window(window)?;

    let status = evaluator
        .evaluate(&EvaluationContext::healthy())
        .results()
        .first()
        .map(l2_segmentation::RuleResult::status)
        .ok_or("missing rule result")?;
    assert_eq!(status, EvaluationStatus::Pass);
    Ok(())
}

#[test]
fn commitment_requires_planned_source_interface() -> Result<(), Box<dyn Error>> {
    let plan = l2_segmentation::plan(&input_with_rule(RuleExpectation::Deny, 1)?)?;
    let probe = *plan.probes().first().ok_or("missing probe")?;
    let canary = probe.canary()?;
    let key = key_for(&canary)?;
    let payload = encode(&canary, &key)?;
    let frame = ethernet_frame(&payload);
    let planned = PlannedCanaryFrame::from_probe(probe, &key, &frame)?;
    let wrong = TxCommitment::from_planned_frame(&planned, interface(90)?);
    let expected = TxCommitment::from_planned_frame(&planned, agent_interface(1)?);
    let mut evaluator = Evaluator::new(&plan);

    assert_eq!(
        evaluator.record_commitment(wrong),
        Err(ReceiptError::SourceInterfaceMismatch)
    );
    evaluator.record_commitment(expected)?;
    assert_eq!(
        evaluator
            .evaluate(&EvaluationContext::healthy())
            .results()
            .first()
            .map(l2_segmentation::RuleResult::status),
        Some(EvaluationStatus::Inconclusive)
    );
    Ok(())
}

#[test]
fn absence_window_planned_destination_interface() -> Result<(), Box<dyn Error>> {
    let plan = l2_segmentation::plan(&input_with_rule(RuleExpectation::Deny, 1)?)?;
    let probe = *plan.probes().first().ok_or("missing probe")?;
    let canary = probe.canary()?;
    let key = key_for(&canary)?;
    let payload = encode(&canary, &key)?;
    let frame = ethernet_frame(&payload);
    let planned = PlannedCanaryFrame::from_probe(probe, &key, &frame)?;
    let sender = agent_interface(1)?;
    let commitment = TxCommitment::from_planned_frame(&planned, sender);
    let timing = ObservationWindowTiming::new(
        ClockStamp::new(ClockDomainId::new([0x32; 16])?, 100)?,
        ClockStamp::new(ClockDomainId::new([0x32; 16])?, 200)?,
        ControllerEvent::new(RUN, probe.sequence(), 1)?,
        ControllerEvent::new(RUN, probe.sequence(), 5)?,
        ControllerEvent::new(RUN, probe.sequence(), 7)?,
    )?;
    let wrong_window = ObservationWindowReceipt::new(
        RUN,
        probe.sequence(),
        probe.destination_agent_id(),
        interface(91)?,
        timing,
        0,
        true,
    )?;
    let expected_window = ObservationWindowReceipt::new(
        RUN,
        probe.sequence(),
        probe.destination_agent_id(),
        agent_interface(2)?,
        timing,
        0,
        true,
    )?;
    let mut evaluator = Evaluator::new(&plan);

    evaluator.record_commitment(commitment)?;
    evaluator.record_tx(TxReceipt::new(
        RUN,
        probe.sequence(),
        sender,
        planned.frame_hash(),
        TxTiming::new(
            ClockStamp::new(ClockDomainId::new([0x31; 16])?, 150)?,
            ControllerEvent::new(RUN, probe.sequence(), 3)?,
        ),
    )?)?;
    assert_eq!(
        evaluator.record_window(wrong_window),
        Err(ReceiptError::DestinationInterfaceMismatch)
    );
    evaluator.record_window(expected_window)?;
    assert_eq!(
        evaluator
            .evaluate(&EvaluationContext::healthy())
            .results()
            .first()
            .map(l2_segmentation::RuleResult::status),
        Some(EvaluationStatus::Pass)
    );
    Ok(())
}

#[test]
fn planned_canary_unrelated_authenticated_payload() -> Result<(), Box<dyn Error>> {
    let plan = l2_segmentation::plan(&input_with_rule(RuleExpectation::Allow, 1)?)?;
    let probe = *plan.probes().first().ok_or("missing probe")?;
    let canary = probe.canary()?;
    let key = key_for(&canary)?;
    let frame = ethernet_frame(&[0x66; l2_canary::WIRE_LEN]);

    assert!(PlannedCanaryFrame::from_probe(probe, &key, &frame).is_err());
    Ok(())
}
