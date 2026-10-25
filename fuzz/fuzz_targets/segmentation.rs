#![no_main]

use l2_canary::{AgentKey, ID_LEN, SessionKey, WIRE_LEN};
use l2_segmentation::{
    Agent, AgentId, CaptureQuality, ClockDomainId, ClockStamp, ControllerEvent, DirectedRule,
    EvaluationContext, Evaluator, EvidenceSourceId, InterfaceBindingRequest,
    ObservationWindowReceipt, ObservationWindowTiming, PacketReference, PlanInput,
    PlannedCanaryFrame, RuleExpectation, SegmentId, TxCommitment, TxReceipt, TxTiming,
};
use libfuzzer_sys::fuzz_target;

const MAX_RAW_OBSERVATIONS: usize = 32;
const MAX_AUTHENTICATED_OBSERVATIONS: usize = 64;

// Keep planning input small while varying expectations and directed paths
fuzz_target!(|data: &[u8]| {
    let mut seed = Seed::new(data);
    let Some(input) = plan_input(&mut seed) else {
        return;
    };
    let Ok(plan) = input.plan() else {
        return;
    };

    let Some(first_probe) = plan.probes().first() else {
        return;
    };
    let Ok(first_canary) = first_probe.canary() else {
        return;
    };
    let Ok(agent_key) = AgentKey::new(first_probe.source_agent_id(), &[0x42; 32]) else {
        return;
    };
    let Ok(raw_key) = SessionKey::derive(&agent_key, &first_canary.identity()) else {
        return;
    };
    let Some((raw_window, raw_interface, raw_observed_at)) = observation_claim(&first_canary)
    else {
        return;
    };
    let mut evaluator = Evaluator::new(&plan);
    let mut evidence_sequence = 1_u64;
    let context = evaluation_context(&mut seed);

    // Evaluate the empty observation state before any authenticated receipt exists
    let _ = evaluator.evaluate(&context);

    // Every raw chunk must pass through authentication and structural checks
    for observation in data.chunks(WIRE_LEN).take(MAX_RAW_OBSERVATIONS) {
        let Some(packet) = fuzz_packet_reference(evidence_sequence) else {
            continue;
        };
        let _ = evaluator.observe_wire(
            observation,
            &raw_key,
            raw_window,
            raw_interface,
            raw_observed_at,
            packet,
        );
        evidence_sequence = evidence_sequence.saturating_add(1);
    }

    // Encode planned probes through the production wire encoder before observing them
    for probe in plan.probes().iter().take(MAX_AUTHENTICATED_OBSERVATIONS) {
        let Ok(canary) = probe.canary() else {
            continue;
        };
        let Ok(agent_key) = AgentKey::new(probe.source_agent_id(), &[0x42; 32]) else {
            continue;
        };
        let Ok(key) = SessionKey::derive(&agent_key, &canary.identity()) else {
            continue;
        };
        let Ok(wire) = l2_canary::encode(&canary, &key) else {
            continue;
        };
        let mut frame = Vec::with_capacity(14 + wire.len());
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        frame.extend_from_slice(&l2_canary::ETHER_TYPE.to_be_bytes());
        frame.extend_from_slice(&wire);
        let Ok(planned) = PlannedCanaryFrame::from_probe(*probe, &key, &frame) else {
            continue;
        };
        let commitment = TxCommitment::from_planned_frame(&planned, probe.source_interface());
        if evaluator.record_commitment(commitment).is_err() {
            continue;
        }
        let Ok(local_domain) = ClockDomainId::new([0x33; ID_LEN]) else {
            continue;
        };
        let Ok(local_commit) = ClockStamp::new(local_domain, 15) else {
            continue;
        };
        let Ok(committed_event) = ControllerEvent::new(
            canary.run_id().into_bytes(),
            canary.sequence(),
            canary.sequence().saturating_mul(10).saturating_add(3),
        ) else {
            continue;
        };
        let Ok(transmit) = TxReceipt::new(
            canary.run_id().into_bytes(),
            canary.sequence(),
            probe.source_interface(),
            commitment.frame_hash(),
            TxTiming::new(local_commit, committed_event),
        ) else {
            continue;
        };
        if evaluator.record_tx(transmit).is_err() {
            continue;
        }
        let Some((window, observed_interface, observed_at)) = observation_claim(&canary) else {
            continue;
        };
        let Some(packet) = fuzz_packet_reference(evidence_sequence) else {
            continue;
        };
        let _ =
            evaluator.observe_wire(&wire, &key, window, observed_interface, observed_at, packet);
        evidence_sequence = evidence_sequence.saturating_add(1);

        // A tag mutation remains an arbitrary wire observation and cannot authenticate
        let mut tampered = wire;
        if let Some(last) = tampered.last_mut() {
            *last ^= seed.byte().max(1);
        }
        let Some(packet) = fuzz_packet_reference(evidence_sequence) else {
            continue;
        };
        let _ = evaluator.observe_wire(
            &tampered,
            &key,
            window,
            observed_interface,
            observed_at,
            packet,
        );
        evidence_sequence = evidence_sequence.saturating_add(1);
    }

    // Re-evaluate after raw, authenticated, duplicate, and tampered observations
    let _ = evaluator.evaluate(&context);
});

fn fuzz_packet_reference(packet_number: u64) -> Option<PacketReference> {
    PacketReference::new(EvidenceSourceId::from_bytes([0xf0; 32]), packet_number).ok()
}

fn plan_input(seed: &mut Seed<'_>) -> Option<PlanInput> {
    let mut run_id = seed.array::<ID_LEN>();
    mark_first(&mut run_id, 0x52);

    let segments = vec![SegmentId::new(0), SegmentId::new(1)];
    let agents_per_segment = usize::from(seed.byte() % 2).saturating_add(1);
    let mut agents = Vec::with_capacity(agents_per_segment.saturating_mul(2));
    for segment in [0_u8, 1_u8] {
        for ordinal in 0..agents_per_segment {
            let mut identity = seed.array::<ID_LEN>();
            let base_marker: u8 = if segment == 0 { 0xa0 } else { 0xb0 };
            let marker = if ordinal == 0 {
                base_marker
            } else {
                base_marker.saturating_add(1)
            };
            mark_first(&mut identity, marker);
            let agent_id = AgentId::new(identity).ok()?;
            let interface = InterfaceBindingRequest::new(1, 2, u32::from(marker), 1).ok()?;
            agents.push(Agent::new(agent_id, SegmentId::new(segment), interface));
        }
    }

    let attempts = (seed.byte() % 4).saturating_add(1);
    let expectation = if seed.byte() & 1 == 0 {
        RuleExpectation::Allow
    } else {
        RuleExpectation::Deny
    };
    let mut rules = vec![DirectedRule::new(
        SegmentId::new(0),
        SegmentId::new(1),
        expectation,
        attempts,
    )];
    if seed.byte() & 1 != 0 {
        rules.push(DirectedRule::new(
            SegmentId::new(1),
            SegmentId::new(0),
            opposite(expectation),
            attempts,
        ));
    }

    let mut input = PlanInput::for_replay(run_id).ok()?;
    input.segments = segments;
    input.agents = agents;
    input.rules = rules;
    Some(input)
}

fn evaluation_context(seed: &mut Seed<'_>) -> EvaluationContext {
    let flags = seed.byte();
    let capture_quality = match flags % 3 {
        0 => CaptureQuality::Complete,
        1 => CaptureQuality::Incomplete,
        _ => CaptureQuality::Dropped,
    };
    EvaluationContext::new(
        flags & 1 != 0,
        flags & 2 != 0,
        capture_quality,
        flags & 4 != 0,
    )
}

// Keep every wire claim scoped to a real destination and one receiver clock domain
fn observation_claim(
    canary: &l2_canary::Canary,
) -> Option<(
    ObservationWindowReceipt,
    InterfaceBindingRequest,
    ClockStamp,
)> {
    let receiver_interface =
        InterfaceBindingRequest::new(1, 2, u32::from(canary.destination_agent_id().bytes()[0]), 1)
            .ok()?;
    let clock_domain = ClockDomainId::new([0x22; ID_LEN]).ok()?;
    let window = ObservationWindowReceipt::new(
        canary.run_id().into_bytes(),
        canary.sequence(),
        canary.destination_agent_id(),
        receiver_interface,
        ObservationWindowTiming::new(
            ClockStamp::new(clock_domain, 10).ok()?,
            ClockStamp::new(clock_domain, 30).ok()?,
            ControllerEvent::new(
                canary.run_id().into_bytes(),
                canary.sequence(),
                canary.sequence().saturating_mul(10).saturating_add(1),
            )
            .ok()?,
            ControllerEvent::new(
                canary.run_id().into_bytes(),
                canary.sequence(),
                canary.sequence().saturating_mul(10).saturating_add(5),
            )
            .ok()?,
            ControllerEvent::new(
                canary.run_id().into_bytes(),
                canary.sequence(),
                canary.sequence().saturating_mul(10).saturating_add(7),
            )
            .ok()?,
        )
        .ok()?,
        0,
        true,
    )
    .ok()?;
    let observed_at = ClockStamp::new(clock_domain, 20).ok()?;
    Some((window, receiver_interface, observed_at))
}

const fn opposite(expectation: RuleExpectation) -> RuleExpectation {
    match expectation {
        RuleExpectation::Allow => RuleExpectation::Deny,
        RuleExpectation::Deny => RuleExpectation::Allow,
    }
}

const fn mark_first(bytes: &mut [u8; ID_LEN], marker: u8) {
    if let Some(first) = bytes.first_mut() {
        *first = marker;
    }
}

struct Seed<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Seed<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn byte(&mut self) -> u8 {
        let value = self.data.get(self.offset).map_or(0, |byte| *byte);
        self.offset = self.offset.saturating_add(1);
        value
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut output = [0_u8; N];
        for byte in &mut output {
            *byte = self.byte();
        }
        output
    }
}
