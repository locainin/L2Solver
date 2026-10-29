use std::error::Error;

use l2_canary::AgentId;
use l2_lab::{VirtualEndpoint, VlanId};
use l2_onpath::Budget;
use l2_segmentation::{
    Agent, DirectedRule, InterfaceBindingRequest, Plan, PlanInput, RuleExpectation, SegmentId,
};

pub const SYNTHETIC_KEY: [u8; 32] = [0x65; 32];

pub fn scenario() -> Result<(Plan, Vec<VirtualEndpoint>), Box<dyn Error>> {
    let first = SegmentId::new(1);
    let second = SegmentId::new(2);
    let mut input = PlanInput::for_replay([0x22; 16])?;
    input.segments.extend([first, second]);
    let agents = [
        Agent::new(AgentId::new([1; 16])?, first, binding(1)?),
        Agent::new(AgentId::new([2; 16])?, first, binding(2)?),
        Agent::new(AgentId::new([3; 16])?, second, binding(3)?),
    ];
    input.agents.extend(agents);
    input.rules.extend([
        DirectedRule::new(first, first, RuleExpectation::Allow, 1),
        DirectedRule::new(first, second, RuleExpectation::Deny, 1),
        DirectedRule::new(second, first, RuleExpectation::Deny, 1),
    ]);
    let endpoints = agents
        .into_iter()
        .enumerate()
        .map(|(index, agent)| {
            let host = u8::try_from(index + 1)?;
            let vlan = if agent.segment() == first { 10 } else { 20 };
            Ok(VirtualEndpoint::new(
                agent.id(),
                agent.interface(),
                [0x02, 0, 0, 0, 0, host],
                VlanId::new(vlan)?,
            )?)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    Ok((input.plan()?, endpoints))
}

pub fn binding(number: u32) -> Result<InterfaceBindingRequest, Box<dyn Error>> {
    Ok(InterfaceBindingRequest::new(1, 1, number, 1)?)
}

pub fn budget() -> Result<Budget, Box<dyn Error>> {
    Ok(Budget::new(32, 10_000, 100)?)
}
