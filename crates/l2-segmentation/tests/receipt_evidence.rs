use std::error::Error;

use l2_canary::{AgentKey, MIN_KEY_LEN, SessionKey, encode};
use l2_helper_protocol::InterfaceBindingRequest;
use l2_segmentation::{
    Agent, AgentId, ClockDomainId, ClockStamp, ControllerEvent, DirectedRule, EvaluationContext,
    EvaluationStatus, Evaluator, ObservationWindowReceipt, ObservationWindowTiming, Plan,
    PlanInput, PlannedCanaryFrame, Probe, ReceiptError, RuleExpectation, SegmentId, TxCommitment,
    TxReceipt, TxTiming,
};

const RUN: [u8; 16] = [0x41; 16];
const SOURCE: [u8; 16] = [0x51; 16];
const DESTINATION: [u8; 16] = [0x61; 16];

const fn destination() -> Result<AgentId, l2_canary::AgentIdError> {
    AgentId::new(DESTINATION)
}

const fn binding() -> Result<InterfaceBindingRequest, l2_helper_protocol::ProtocolError> {
    InterfaceBindingRequest::new(1, 2, 3, 1)
}

fn clock_stamp(domain: u8, ticks: u64) -> Result<ClockStamp, ReceiptError> {
    ClockStamp::new(ClockDomainId::new([domain; 16])?, ticks)
}

fn tx_timing(sequence: u64, ticks: u64, event: u64) -> Result<TxTiming, ReceiptError> {
    Ok(TxTiming::new(
        clock_stamp(11, ticks)?,
        ControllerEvent::new(RUN, sequence, event)?,
    ))
}

fn window_timing(
    sequence: u64,
    interval: (u64, u64),
    events: (u64, u64, u64),
) -> Result<ObservationWindowTiming, ReceiptError> {
    ObservationWindowTiming::new(
        clock_stamp(22, interval.0)?,
        clock_stamp(22, interval.1)?,
        ControllerEvent::new(RUN, sequence, events.0)?,
        ControllerEvent::new(RUN, sequence, events.1)?,
        ControllerEvent::new(RUN, sequence, events.2)?,
    )
}

fn planned_commitment(probe: &Probe, marker: u8) -> Result<TxCommitment, Box<dyn Error>> {
    let canary = probe.canary()?;
    let agent_key = AgentKey::new(canary.source_agent_id(), &[0x35; MIN_KEY_LEN])?;
    let key = SessionKey::derive(&agent_key, &canary.identity())?;
    let payload = encode(&canary, &key)?;
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, marker]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 1, marker]);
    frame.extend_from_slice(&l2_canary::ETHER_TYPE.to_be_bytes());
    frame.extend_from_slice(&payload);
    let planned = PlannedCanaryFrame::from_probe(*probe, &key, &frame)?;
    Ok(TxCommitment::from_planned_frame(&planned, binding()?))
}

fn deny_plan() -> Result<Plan, Box<dyn Error>> {
    let mut input = PlanInput::for_replay(RUN)?;
    input.segments = vec![SegmentId::new(1), SegmentId::new(2)];
    input.agents = vec![
        Agent::new(AgentId::new(SOURCE)?, SegmentId::new(1), binding()?),
        Agent::new(AgentId::new(DESTINATION)?, SegmentId::new(2), binding()?),
    ];
    input.rules = vec![DirectedRule::new(
        SegmentId::new(1),
        SegmentId::new(2),
        RuleExpectation::Deny,
        2,
    )];
    Ok(input.plan()?)
}

fn status(evaluator: &Evaluator) -> Result<EvaluationStatus, &'static str> {
    evaluator
        .evaluate(&EvaluationContext::healthy())
        .results()
        .first()
        .map(l2_segmentation::RuleResult::status)
        .ok_or("missing directed result")
}

fn record_complete_absence(evaluator: &mut Evaluator, plan: &Plan) -> Result<(), Box<dyn Error>> {
    for probe in plan.probes() {
        let sequence = probe.sequence();
        let commitment = planned_commitment(probe, u8::try_from(sequence).unwrap_or(1))?;
        let frame_hash = commitment.frame_hash();
        evaluator.record_commitment(commitment)?;
        evaluator.record_tx(TxReceipt::new(
            RUN,
            sequence,
            binding()?,
            frame_hash,
            tx_timing(sequence, 100 + sequence, sequence * 10 + 3)?,
        )?)?;
        evaluator.record_window(ObservationWindowReceipt::new(
            RUN,
            sequence,
            destination()?,
            binding()?,
            window_timing(
                sequence,
                (90 + sequence, 200 + sequence),
                (sequence * 10 + 1, sequence * 10 + 5, sequence * 10 + 7),
            )?,
            0,
            true,
        )?)?;
    }
    Ok(())
}

#[test]
fn healthy_silence_without_receipts_inconclusive() -> Result<(), Box<dyn Error>> {
    let plan = deny_plan()?;
    let evaluator = Evaluator::new(&plan);

    assert_eq!(status(&evaluator)?, EvaluationStatus::Inconclusive);
    Ok(())
}

#[test]
fn every_probe_receipt_deny_pass() -> Result<(), Box<dyn Error>> {
    let plan = deny_plan()?;
    let mut evaluator = Evaluator::new(&plan);
    record_complete_absence(&mut evaluator, &plan)?;

    let report = evaluator.evaluate(&EvaluationContext::healthy());
    let result = report.results().first().ok_or("missing directed result")?;
    assert_eq!(result.status(), EvaluationStatus::Pass);
    assert_eq!(result.absence_evidence().len(), plan.probes().len());
    for evidence in result.absence_evidence() {
        assert_eq!(evidence.canary().run_id().into_bytes(), RUN);
        assert_eq!(evidence.source_interface(), binding()?);
        assert_eq!(evidence.observation_interface(), binding()?);
        assert_eq!(evidence.frame_sha256(), evidence.transmit().frame_hash());
        assert!(
            evidence
                .window()
                .proves_complete_absence_for(evidence.transmit())
        );
    }
    Ok(())
}

#[test]
fn missing_tx_inconclusive() -> Result<(), Box<dyn Error>> {
    let plan = deny_plan()?;
    let mut evaluator = Evaluator::new(&plan);
    let first = plan.probes().first().ok_or("missing planned probe")?;

    evaluator.record_window(ObservationWindowReceipt::new(
        RUN,
        first.sequence(),
        destination()?,
        binding()?,
        window_timing(first.sequence(), (90, 200), (1, 5, 7))?,
        0,
        true,
    )?)?;

    assert_eq!(status(&evaluator)?, EvaluationStatus::Inconclusive);
    Ok(())
}

#[test]
fn receipt_without_commitment_is_rejected() -> Result<(), Box<dyn Error>> {
    let plan = deny_plan()?;
    let mut evaluator = Evaluator::new(&plan);
    let probe = plan.probes().first().ok_or("missing planned probe")?;
    let receipt = TxReceipt::new(
        RUN,
        probe.sequence(),
        binding()?,
        [1; 32],
        tx_timing(probe.sequence(), 100, 3)?,
    )?;

    assert_eq!(
        evaluator.record_tx(receipt),
        Err(ReceiptError::MissingCommitment)
    );
    assert_eq!(status(&evaluator)?, EvaluationStatus::Inconclusive);
    Ok(())
}

#[test]
fn mismatched_receipt_hash_is_rejected() -> Result<(), Box<dyn Error>> {
    let plan = deny_plan()?;
    let mut evaluator = Evaluator::new(&plan);
    let probe = plan.probes().first().ok_or("missing planned probe")?;

    let commitment = planned_commitment(probe, 1)?;
    evaluator.record_commitment(commitment)?;
    let receipt = TxReceipt::new(
        RUN,
        probe.sequence(),
        binding()?,
        [2; 32],
        tx_timing(probe.sequence(), 100, 3)?,
    )?;
    assert_eq!(
        evaluator.record_tx(receipt),
        Err(ReceiptError::CommitmentMismatch)
    );
    assert_eq!(status(&evaluator)?, EvaluationStatus::Inconclusive);
    Ok(())
}

#[test]
fn matching_receipt_window_permit_pass() -> Result<(), Box<dyn Error>> {
    let plan = deny_plan()?;
    let mut evaluator = Evaluator::new(&plan);
    for (marker, probe) in plan.probes().iter().enumerate() {
        let commitment = planned_commitment(probe, u8::try_from(marker + 7)?)?;
        let hash = commitment.frame_hash();
        evaluator.record_commitment(commitment)?;
        evaluator.record_tx(TxReceipt::new(
            RUN,
            probe.sequence(),
            binding()?,
            hash,
            tx_timing(
                probe.sequence(),
                100 + probe.sequence(),
                probe.sequence() * 10 + 3,
            )?,
        )?)?;
        evaluator.record_window(ObservationWindowReceipt::new(
            RUN,
            probe.sequence(),
            destination()?,
            binding()?,
            window_timing(
                probe.sequence(),
                (90, 200),
                (
                    probe.sequence() * 10 + 1,
                    probe.sequence() * 10 + 5,
                    probe.sequence() * 10 + 7,
                ),
            )?,
            0,
            true,
        )?)?;
    }

    assert_eq!(status(&evaluator)?, EvaluationStatus::Pass);
    Ok(())
}

#[test]
fn conflicting_late_commitments_rejected() -> Result<(), Box<dyn Error>> {
    let plan = deny_plan()?;
    let mut evaluator = Evaluator::new(&plan);
    let probe = plan.probes().first().ok_or("missing planned probe")?;
    let commitment = planned_commitment(probe, 3)?;
    let conflicting = planned_commitment(probe, 4)?;

    evaluator.record_commitment(commitment)?;
    assert_eq!(
        evaluator.record_commitment(conflicting),
        Err(ReceiptError::ConflictingCommitment)
    );
    evaluator.record_tx(TxReceipt::new(
        RUN,
        probe.sequence(),
        binding()?,
        commitment.frame_hash(),
        tx_timing(probe.sequence(), 100, 3)?,
    )?)?;
    assert_eq!(
        evaluator.record_commitment(commitment),
        Err(ReceiptError::LateCommitment)
    );
    Ok(())
}

#[test]
fn lossy_window_stays_inconclusive() -> Result<(), Box<dyn Error>> {
    let plan = deny_plan()?;
    let mut evaluator = Evaluator::new(&plan);
    for probe in plan.probes() {
        let commitment = planned_commitment(probe, 1)?;
        let hash = commitment.frame_hash();
        evaluator.record_commitment(commitment)?;
        evaluator.record_tx(TxReceipt::new(
            RUN,
            probe.sequence(),
            binding()?,
            hash,
            tx_timing(probe.sequence(), 100, probe.sequence() * 10 + 3)?,
        )?)?;
        evaluator.record_window(ObservationWindowReceipt::new(
            RUN,
            probe.sequence(),
            destination()?,
            binding()?,
            window_timing(
                probe.sequence(),
                (90, 200),
                (
                    probe.sequence() * 10 + 1,
                    probe.sequence() * 10 + 5,
                    probe.sequence() * 10 + 7,
                ),
            )?,
            1,
            true,
        )?)?;
    }

    assert_eq!(status(&evaluator)?, EvaluationStatus::Inconclusive);
    Ok(())
}

#[test]
fn receipt_match_planned_probe() -> Result<(), Box<dyn Error>> {
    let plan = deny_plan()?;
    let mut evaluator = Evaluator::new(&plan);
    let receipt = TxReceipt::new(RUN, 99, binding()?, [1; 32], tx_timing(99, 100, 3)?)?;

    assert_eq!(
        evaluator.record_tx(receipt),
        Err(ReceiptError::UnknownProbe)
    );
    Ok(())
}

#[test]
fn commitment_rejects_sentinel_invalid_frame() -> Result<(), Box<dyn Error>> {
    let frame = [0_u8; 14];
    assert_eq!(
        TxCommitment::from_frame_claim([0; 16], 1, binding()?, &frame),
        Err(ReceiptError::ZeroRunId)
    );
    assert_eq!(
        TxCommitment::from_frame_claim(RUN, 0, binding()?, &frame),
        Err(ReceiptError::ZeroSequence)
    );
    assert_eq!(
        TxCommitment::from_frame_claim(RUN, 1, binding()?, &[]),
        Err(ReceiptError::InvalidFrame)
    );

    let commitment = TxCommitment::from_frame_claim(RUN, 1, binding()?, &frame)?;
    assert_eq!(commitment.run_id(), RUN);
    assert_eq!(commitment.sequence(), 1);
    assert_eq!(commitment.interface(), binding()?);
    assert_ne!(commitment.frame_hash(), [0; 32]);
    assert_eq!(commitment.frame_length(), u64::try_from(frame.len())?);
    assert_eq!(commitment.planned_canary(), None);
    Ok(())
}

#[test]
fn controller_tx_cannot_reused_probe() -> Result<(), Box<dyn Error>> {
    let plan = deny_plan()?;
    let mut evaluator = Evaluator::new(&plan);
    for probe in plan.probes() {
        let commitment = planned_commitment(probe, u8::try_from(probe.sequence())?)?;
        evaluator.record_commitment(commitment)?;
        let receipt = TxReceipt::new(
            RUN,
            probe.sequence(),
            binding()?,
            commitment.frame_hash(),
            tx_timing(probe.sequence(), 100 + probe.sequence(), 3)?,
        )?;
        if probe.sequence() == 1 {
            evaluator.record_tx(receipt)?;
        } else {
            assert_eq!(
                evaluator.record_tx(receipt),
                Err(ReceiptError::ControllerEventReuse { ordinal: 3 })
            );
        }
    }
    Ok(())
}

#[test]
fn failed_window_event_reservation_atomic() -> Result<(), Box<dyn Error>> {
    let plan = deny_plan()?;
    let mut evaluator = Evaluator::new(&plan);
    let first = plan.probes().first().ok_or("missing first probe")?;
    let second = plan.probes().get(1).ok_or("missing second probe")?;
    evaluator.record_window(ObservationWindowReceipt::new(
        RUN,
        first.sequence(),
        destination()?,
        binding()?,
        window_timing(first.sequence(), (90, 200), (11, 15, 17))?,
        0,
        true,
    )?)?;
    let colliding = ObservationWindowReceipt::new(
        RUN,
        second.sequence(),
        destination()?,
        binding()?,
        window_timing(second.sequence(), (90, 200), (14, 15, 18))?,
        0,
        true,
    )?;
    assert_eq!(
        evaluator.record_window(colliding),
        Err(ReceiptError::ControllerEventReuse { ordinal: 15 })
    );

    evaluator.record_window(ObservationWindowReceipt::new(
        RUN,
        second.sequence(),
        destination()?,
        binding()?,
        window_timing(second.sequence(), (90, 200), (14, 16, 18))?,
        0,
        true,
    )?)?;
    Ok(())
}

#[test]
fn probe_controller_role() -> Result<(), Box<dyn Error>> {
    let plan = deny_plan()?;
    let probe = plan.probes().first().ok_or("missing probe")?;
    let commitment = planned_commitment(probe, 21)?;
    let mut evaluator = Evaluator::new(&plan);
    evaluator.record_commitment(commitment)?;
    evaluator.record_tx(TxReceipt::new(
        RUN,
        probe.sequence(),
        binding()?,
        commitment.frame_hash(),
        tx_timing(probe.sequence(), 100, 13)?,
    )?)?;

    let conflicting = ObservationWindowReceipt::new(
        RUN,
        probe.sequence(),
        destination()?,
        binding()?,
        window_timing(probe.sequence(), (90, 200), (13, 15, 17))?,
        0,
        true,
    )?;
    assert_eq!(
        evaluator.record_window(conflicting),
        Err(ReceiptError::ControllerEventReuse { ordinal: 13 })
    );
    Ok(())
}

#[test]
fn duplicate_receipts_ledgers_per_evaluator() -> Result<(), Box<dyn Error>> {
    let plan = deny_plan()?;
    let probe = plan.probes().first().ok_or("missing probe")?;
    let commitment = planned_commitment(probe, 22)?;
    let transmit = TxReceipt::new(
        RUN,
        probe.sequence(),
        binding()?,
        commitment.frame_hash(),
        tx_timing(probe.sequence(), 100, 13)?,
    )?;
    let window = ObservationWindowReceipt::new(
        RUN,
        probe.sequence(),
        destination()?,
        binding()?,
        window_timing(probe.sequence(), (90, 200), (11, 15, 17))?,
        0,
        true,
    )?;
    let mut first = Evaluator::new(&plan);
    let mut second = Evaluator::new(&plan);

    for evaluator in [&mut first, &mut second] {
        evaluator.record_commitment(commitment)?;
        evaluator.record_tx(transmit)?;
        evaluator.record_window(window)?;
    }

    first.record_tx(transmit)?;
    first.record_window(window)?;
    Ok(())
}

#[test]
fn maximum_controller_accepted_without_wrap() -> Result<(), Box<dyn Error>> {
    let plan = deny_plan()?;
    let probe = plan.probes().first().ok_or("missing probe")?;
    let commitment = planned_commitment(probe, 23)?;
    let transmit = TxReceipt::new(
        RUN,
        probe.sequence(),
        binding()?,
        commitment.frame_hash(),
        tx_timing(probe.sequence(), 100, u64::MAX - 2)?,
    )?;
    let window = ObservationWindowReceipt::new(
        RUN,
        probe.sequence(),
        destination()?,
        binding()?,
        window_timing(
            probe.sequence(),
            (90, 200),
            (u64::MAX - 3, u64::MAX - 1, u64::MAX),
        )?,
        0,
        true,
    )?;
    let mut evaluator = Evaluator::new(&plan);

    assert!(window.causally_covers(transmit));
    evaluator.record_commitment(commitment)?;
    evaluator.record_tx(transmit)?;
    evaluator.record_window(window)?;
    Ok(())
}
