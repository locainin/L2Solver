use std::error::Error;

use l2_canary::{
    AgentId, AgentKey, Canary, CanaryIdentity, MIN_KEY_LEN, RunId, SessionKey, encode,
};
use l2_helper_protocol::InterfaceBindingRequest;
use l2_segmentation::{
    Agent, CaptureQuality, ClockDomainId, ClockStamp, ControllerEvent, EvaluationContext,
    Evaluator, EvidenceSourceId, ObservationDisposition, ObservationWindowReceipt,
    ObservationWindowTiming, PacketReference, PlanInput, PlannedCanaryFrame, RuleExpectation,
    SegmentId, TxCommitment, TxReceipt, TxTiming,
};

pub const RUN: [u8; 16] = [0x10; 16];
const KEY_BYTES: [u8; MIN_KEY_LEN] = [0x55; MIN_KEY_LEN];

pub fn agent_interface(
    byte: u8,
) -> Result<InterfaceBindingRequest, l2_helper_protocol::ProtocolError> {
    InterfaceBindingRequest::new(1, 2, u32::from(byte), 1)
}

pub fn packet_ref(source: u8, packet_number: u64) -> Result<PacketReference, Box<dyn Error>> {
    let source = EvidenceSourceId::from_bytes([source; 32]);
    Ok(PacketReference::new(source, packet_number)?)
}

// Agents are deliberately tiny so planner tests focus on direction and order
pub fn agent(byte: u8, segment: u8) -> Result<Agent, Box<dyn Error>> {
    Ok(Agent::new(
        AgentId::new([byte; 16])?,
        SegmentId::new(segment),
        agent_interface(byte)?,
    ))
}

pub fn input_with_rule(
    expectation: RuleExpectation,
    attempts: u8,
) -> Result<PlanInput, Box<dyn Error>> {
    let mut input = PlanInput::for_replay(RUN)?;
    input
        .segments
        .extend([SegmentId::new(1), SegmentId::new(2)]);
    input.agents.extend([agent(1, 1)?, agent(2, 2)?]);
    input.rules.push(l2_segmentation::DirectedRule::new(
        SegmentId::new(1),
        SegmentId::new(2),
        expectation,
        attempts,
    ));
    Ok(input)
}

pub const fn healthy() -> EvaluationContext {
    EvaluationContext::new(true, true, CaptureQuality::Complete, false)
}

pub fn key() -> Result<SessionKey, Box<dyn Error>> {
    let identity = CanaryIdentity::new(
        RunId::from_recorded(RUN)?,
        AgentId::new([1; 16])?,
        AgentId::new([2; 16])?,
    )?;
    let canary = Canary::new(identity, 1, [0; 16])?;
    key_for(&canary)
}

// A scoped key lets mismatch tests authenticate each altered identity first
pub fn key_for(canary: &Canary) -> Result<SessionKey, Box<dyn Error>> {
    let agent_key = AgentKey::new(canary.source_agent_id(), &KEY_BYTES)?;
    Ok(SessionKey::derive(&agent_key, &canary.identity())?)
}

pub fn observe(
    evaluator: &mut Evaluator,
    canary: &Canary,
    evidence_sequence: u64,
) -> Result<ObservationDisposition, Box<dyn Error>> {
    let key = key_for(canary)?;
    let wire = encode(canary, &key)?;
    record_transmit(evaluator, canary, &key, &wire)?;
    observe_after_transmit(evaluator, canary, &key, &wire, evidence_sequence)
}

pub fn observe_after_transmit(
    evaluator: &mut Evaluator,
    canary: &Canary,
    key: &SessionKey,
    wire: &[u8],
    evidence_sequence: u64,
) -> Result<ObservationDisposition, Box<dyn Error>> {
    let (window, interface, observed_at) = observation_claim(canary)?;
    Ok(evaluator.observe_wire(
        wire,
        key,
        window,
        interface,
        observed_at,
        packet_ref(0x88, evidence_sequence)?,
    )?)
}

pub fn record_transmit(
    evaluator: &mut Evaluator,
    canary: &Canary,
    key: &SessionKey,
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    let Some(probe) = evaluator
        .plan()
        .probes()
        .iter()
        .copied()
        .find(|probe| probe.canary().ok().as_ref() == Some(canary))
    else {
        return Ok(());
    };
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&l2_canary::ETHER_TYPE.to_be_bytes());
    frame.extend_from_slice(payload);
    let planned = PlannedCanaryFrame::from_probe(probe, key, &frame)?;
    let commitment = TxCommitment::from_planned_frame(&planned, probe.source_interface());
    evaluator.record_commitment(commitment)?;
    evaluator.record_tx(TxReceipt::new(
        canary.run_id().into_bytes(),
        canary.sequence(),
        probe.source_interface(),
        planned.frame_hash(),
        TxTiming::new(
            ClockStamp::new(ClockDomainId::new([0x33; 16])?, 150)?,
            ControllerEvent::new(
                canary.run_id().into_bytes(),
                canary.sequence(),
                canary.sequence() * 10 + 3,
            )?,
        ),
    )?)?;
    Ok(())
}

pub fn observation_claim(
    canary: &Canary,
) -> Result<
    (
        ObservationWindowReceipt,
        InterfaceBindingRequest,
        ClockStamp,
    ),
    Box<dyn Error>,
> {
    let run = canary.run_id().into_bytes();
    let interface = agent_interface(canary.destination_agent_id().bytes()[0])?;
    let domain = ClockDomainId::new([0x44; 16])?;
    let window = ObservationWindowReceipt::new(
        run,
        canary.sequence(),
        canary.destination_agent_id(),
        interface,
        ObservationWindowTiming::new(
            ClockStamp::new(domain, 100)?,
            ClockStamp::new(domain, 200)?,
            ControllerEvent::new(run, canary.sequence(), canary.sequence() * 10 + 1)?,
            ControllerEvent::new(run, canary.sequence(), canary.sequence() * 10 + 5)?,
            ControllerEvent::new(run, canary.sequence(), canary.sequence() * 10 + 7)?,
        )?,
        0,
        true,
    )?;
    Ok((window, interface, ClockStamp::new(domain, 150)?))
}
