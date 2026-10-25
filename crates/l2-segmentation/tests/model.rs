use l2_segmentation::{
    Agent, AgentId, DirectedRule, InterfaceBindingRequest, Plan, PlanInput, RuleExpectation,
    SegmentId, plan,
};

#[test]
fn agent_id_preserves_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let source_id = AgentId::new([0x2a; 16])?;

    // Identity conversions must retain every byte instead of returning a default array
    assert_eq!(source_id.bytes(), [0x2a; 16]);
    assert_eq!(source_id.as_bytes(), &[0x2a; 16]);
    let converted_id: [u8; 16] = source_id.into();
    assert_eq!(converted_id, [0x2a; 16]);
    Ok(())
}

#[test]
fn segment_id_preserves_value() {
    assert_eq!(SegmentId::new(7).get(), 7);
    assert_eq!(SegmentId::from(9).get(), 9);
}

#[test]
fn rule_accessors_preserve_values() {
    let source_segment = SegmentId::new(7);
    let destination_segment = SegmentId::new(9);
    let rule = DirectedRule::new(
        source_segment,
        destination_segment,
        RuleExpectation::Allow,
        2,
    );
    assert_eq!(rule.source(), source_segment);
    assert_eq!(rule.destination(), destination_segment);
    assert_eq!(rule.expectation(), RuleExpectation::Allow);
    assert_eq!(rule.attempts(), 2);
}

#[test]
fn plan_accessors_preserve_collections() -> Result<(), Box<dyn std::error::Error>> {
    let planned = accessor_plan()?;
    let source_segment = SegmentId::new(7);
    let destination_segment = SegmentId::new(9);
    let rule = DirectedRule::new(
        source_segment,
        destination_segment,
        RuleExpectation::Allow,
        2,
    );

    // Plan collections remain available after deterministic sorting
    assert_eq!(planned.run_id(), &[0x11; 16]);
    assert_eq!(planned.segments(), &[source_segment, destination_segment]);
    assert_eq!(planned.agents().len(), 2);
    assert_eq!(planned.rules(), &[rule]);
    assert_eq!(planned.probes().len(), 2);
    Ok(())
}

#[test]
fn probe_accessors_preserve_values() -> Result<(), Box<dyn std::error::Error>> {
    let planned = accessor_plan()?;
    let source_segment = SegmentId::new(7);
    let destination_segment = SegmentId::new(9);
    let source_id = AgentId::new([0x2a; 16])?;
    let destination_id = AgentId::new([0x3b; 16])?;
    let source_interface = InterfaceBindingRequest::new(1, 2, 7, 1)?;
    let destination_interface = InterfaceBindingRequest::new(1, 2, 9, 1)?;

    // The second attempt distinguishes every getter replacement from a valid value
    let probe = planned.probes().get(1).ok_or("missing second probe")?;
    assert_eq!(probe.source_segment(), source_segment);
    assert_eq!(probe.destination_segment(), destination_segment);
    assert_eq!(probe.source_agent_id(), source_id);
    assert_eq!(probe.destination_agent_id(), destination_id);
    assert_eq!(probe.source_interface(), source_interface);
    assert_eq!(probe.destination_interface(), destination_interface);
    assert_eq!(probe.expectation(), RuleExpectation::Allow);
    assert_eq!(probe.attempt(), 2);
    assert_eq!(probe.sequence(), 2);

    assert_eq!(probe.nonce(), second_probe_nonce());
    Ok(())
}

#[test]
fn canary_accessors_preserve_values() -> Result<(), Box<dyn std::error::Error>> {
    let planned = accessor_plan()?;
    let probe = planned.probes().get(1).ok_or("missing second probe")?;

    // Encoding a probe must retain the planned identity and attempt data
    let canary = probe.canary()?;
    assert_eq!(canary.run_id().into_bytes(), [0x11; 16]);
    assert_eq!(canary.source_agent_id().bytes(), [0x2a; 16]);
    assert_eq!(canary.destination_agent_id().bytes(), [0x3b; 16]);
    assert_eq!(canary.sequence(), 2);
    assert_eq!(canary.nonce(), second_probe_nonce());
    Ok(())
}

fn accessor_plan() -> Result<Plan, Box<dyn std::error::Error>> {
    let source_segment = SegmentId::new(7);
    let destination_segment = SegmentId::new(9);
    let source_id = AgentId::new([0x2a; 16])?;
    let destination_id = AgentId::new([0x3b; 16])?;
    let source_interface = InterfaceBindingRequest::new(1, 2, 7, 1)?;
    let destination_interface = InterfaceBindingRequest::new(1, 2, 9, 1)?;

    // Reversed input order keeps the collection checks sensitive to sorting
    let mut input = PlanInput::for_replay([0x11; 16])?;
    input.segments.extend([destination_segment, source_segment]);
    input.agents.extend([
        Agent::new(destination_id, destination_segment, destination_interface),
        Agent::new(source_id, source_segment, source_interface),
    ]);
    input.rules.push(DirectedRule::new(
        source_segment,
        destination_segment,
        RuleExpectation::Allow,
        2,
    ));
    Ok(plan(&input)?)
}

fn second_probe_nonce() -> [u8; 16] {
    let mut nonce = [0_u8; 16];
    nonce[..8].copy_from_slice(&2_u64.to_be_bytes());
    nonce[8..].copy_from_slice(b"l2seg-v1");
    nonce
}
