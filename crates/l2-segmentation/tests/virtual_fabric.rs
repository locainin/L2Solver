use std::{collections::BTreeSet, error::Error};

use l2_canary::{
    AgentId, AgentKey, Canary, CanaryIdentity, MIN_KEY_LEN, RunId, SessionKey, encode,
};
use l2_helper_protocol::InterfaceBindingRequest;
use l2_segmentation::{
    Agent, ClockDomainId, ClockStamp, ControllerEvent, EvaluationContext, EvaluationStatus,
    Evaluator, EvidenceSourceId, ObservationWindowReceipt, ObservationWindowTiming,
    PacketReference, PlanInput, PlannedCanaryFrame, Probe, RuleExpectation, SegmentId,
    TxCommitment, TxReceipt, TxTiming, plan,
};

// This fabric models only forwarding decisions needed by planner tests
struct VirtualFabric {
    allowed: BTreeSet<(SegmentId, SegmentId)>,
}

fn status_for_source(
    report: &l2_segmentation::EvaluationReport,
    source: SegmentId,
) -> Option<EvaluationStatus> {
    report
        .results()
        .iter()
        .find(|result| result.source() == source)
        .map(l2_segmentation::RuleResult::status)
}

fn key(canary: &Canary) -> Result<SessionKey, Box<dyn Error>> {
    let agent_key = AgentKey::new(canary.source_agent_id(), &[0x44; MIN_KEY_LEN])?;
    Ok(SessionKey::derive(&agent_key, &canary.identity())?)
}

impl VirtualFabric {
    fn new(allowed: impl IntoIterator<Item = (SegmentId, SegmentId)>) -> Self {
        Self {
            allowed: allowed.into_iter().collect(),
        }
    }

    fn forward(&self, canary: Canary, source: SegmentId, destination: SegmentId) -> Option<Canary> {
        if self.allowed.contains(&(source, destination)) {
            Some(canary)
        } else {
            None
        }
    }
}

fn exercise_probe(
    fabric: &VirtualFabric,
    evaluator: &mut Evaluator,
    probe: &Probe,
) -> Result<(), Box<dyn Error>> {
    let canary = probe.canary()?;
    let key = key(&canary)?;
    let payload = encode(&canary, &key)?;
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&l2_canary::ETHER_TYPE.to_be_bytes());
    frame.extend_from_slice(&payload);
    let planned_frame = PlannedCanaryFrame::from_probe(*probe, &key, &frame)?;
    let receiver_interface = probe.destination_interface();
    let receiver_domain = ClockDomainId::new([22; 16])?;
    let window = ObservationWindowReceipt::new(
        canary.run_id().into_bytes(),
        probe.sequence(),
        probe.destination_agent_id(),
        receiver_interface,
        ObservationWindowTiming::new(
            ClockStamp::new(receiver_domain, 90 + probe.sequence())?,
            ClockStamp::new(receiver_domain, 200 + probe.sequence())?,
            ControllerEvent::new(
                canary.run_id().into_bytes(),
                canary.sequence(),
                canary.sequence() * 10 + 1,
            )?,
            ControllerEvent::new(
                canary.run_id().into_bytes(),
                canary.sequence(),
                canary.sequence() * 10 + 5,
            )?,
            ControllerEvent::new(
                canary.run_id().into_bytes(),
                canary.sequence(),
                canary.sequence() * 10 + 7,
            )?,
        )?,
        0,
        true,
    )?;
    let binding = probe.source_interface();
    let commitment = TxCommitment::from_planned_frame(&planned_frame, binding);
    evaluator.record_commitment(commitment)?;
    evaluator.record_tx(TxReceipt::new(
        canary.run_id().into_bytes(),
        probe.sequence(),
        binding,
        commitment.frame_hash(),
        TxTiming::new(
            ClockStamp::new(ClockDomainId::new([11; 16])?, 100 + probe.sequence())?,
            ControllerEvent::new(
                canary.run_id().into_bytes(),
                canary.sequence(),
                canary.sequence() * 10 + 3,
            )?,
        ),
    )?)?;
    if let Some(received) =
        fabric.forward(canary, probe.source_segment(), probe.destination_segment())
    {
        let wire = encode(&received, &key)?;
        let _ = evaluator.observe_wire(
            &wire,
            &key,
            window,
            receiver_interface,
            ClockStamp::new(receiver_domain, 150 + probe.sequence())?,
            PacketReference::new(EvidenceSourceId::from_bytes([0x88; 32]), probe.sequence())?,
        )?;
    } else {
        evaluator.record_window(window)?;
    }
    Ok(())
}

#[test]
fn fabric_preserves_allowed_direction() -> Result<(), Box<dyn Error>> {
    let source = SegmentId::new(1);
    let destination = SegmentId::new(2);
    let identity = CanaryIdentity::new(
        RunId::from_recorded([1; 16])?,
        AgentId::new([2; 16])?,
        AgentId::new([3; 16])?,
    )?;
    let canary = Canary::new(identity, 1, [4; 16])?;
    let fabric = VirtualFabric::new([(source, destination)]);

    assert_eq!(fabric.forward(canary, source, destination), Some(canary));
    assert_eq!(fabric.forward(canary, destination, source), None);
    Ok(())
}

#[test]
fn fabric_evaluates_directions_independently() -> Result<(), Box<dyn Error>> {
    let source = SegmentId::new(1);
    let destination = SegmentId::new(2);
    let mut input = PlanInput::for_replay([1; 16])?;
    input.segments.extend([source, destination]);
    input.agents.extend([
        Agent::new(
            AgentId::new([2; 16])?,
            source,
            InterfaceBindingRequest::new(1, 2, 3, 1)?,
        ),
        Agent::new(
            AgentId::new([3; 16])?,
            destination,
            InterfaceBindingRequest::new(1, 2, 4, 1)?,
        ),
    ]);
    input.rules.extend([
        l2_segmentation::DirectedRule::new(source, destination, RuleExpectation::Deny, 1),
        l2_segmentation::DirectedRule::new(destination, source, RuleExpectation::Allow, 1),
    ]);
    let planned = plan(&input)?;
    let fabric = VirtualFabric::new([(destination, source)]);
    let mut evaluator = Evaluator::new(&planned);

    for probe in planned.probes() {
        exercise_probe(&fabric, &mut evaluator, probe)?;
    }

    let report = evaluator.evaluate(&EvaluationContext::healthy());
    let denied = status_for_source(&report, source);
    let allowed = status_for_source(&report, destination);
    assert_eq!(denied, Some(EvaluationStatus::Pass));
    assert_eq!(allowed, Some(EvaluationStatus::Pass));
    Ok(())
}
