use std::error::Error;

use l2_canary::{AgentKey, MIN_KEY_LEN, SessionKey};
use l2_segmentation::{
    Agent, AgentId, DirectedRule, InterfaceBindingRequest, PlanInput, RuleExpectation, SegmentId,
    plan,
};

#[test]
fn planned_agent_directional_session_key() -> Result<(), Box<dyn Error>> {
    let source = AgentId::new([0x20; 16])?;
    let destination = AgentId::new([0x30; 16])?;
    let mut input = PlanInput::for_replay([0x10; 16])?;
    input
        .segments
        .extend([SegmentId::new(1), SegmentId::new(2)]);
    input.agents.extend([
        Agent::new(
            source,
            SegmentId::new(1),
            InterfaceBindingRequest::new(1, 2, 1, 1)?,
        ),
        Agent::new(
            destination,
            SegmentId::new(2),
            InterfaceBindingRequest::new(1, 2, 2, 1)?,
        ),
    ]);
    input.rules.push(DirectedRule::new(
        SegmentId::new(1),
        SegmentId::new(2),
        RuleExpectation::Allow,
        1,
    ));

    let planned = plan(&input)?;
    let probe = planned.probes().first().ok_or("missing planned probe")?;
    let canary = probe.canary()?;
    assert_eq!(canary.source_agent_id(), source);
    let agent_key = AgentKey::new(probe.source_agent_id(), &[0x55; MIN_KEY_LEN])?;
    let key = SessionKey::derive(&agent_key, &canary.identity())?;
    assert!(l2_canary::encode(&canary, &key).is_ok());
    Ok(())
}
