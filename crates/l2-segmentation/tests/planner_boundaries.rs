use l2_segmentation::{
    Agent, AgentId, DirectedRule, InterfaceBindingRequest, MAX_AGENTS, MAX_ATTEMPTS_PER_RULE,
    MAX_PROBES, MAX_SEGMENTS, PlanError, PlanInput, RuleExpectation, SegmentId, plan,
};

fn agent(byte: u8, segment: u8) -> Result<Agent, Box<dyn std::error::Error>> {
    Ok(Agent::new(
        AgentId::new([byte; 16])?,
        SegmentId::new(segment),
        InterfaceBindingRequest::new(1, 2, u32::from(byte), 1)?,
    ))
}

#[test]
fn planner_accepts_collection_probe_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let mut segments = PlanInput::for_replay([1; 16])?;
    for value in 0..MAX_SEGMENTS {
        segments.segments.push(SegmentId::new(u8::try_from(value)?));
    }
    assert!(plan(&segments).is_ok());

    let mut agents = PlanInput::for_replay([2; 16])?;
    agents.segments.push(SegmentId::new(1));
    for value in 0..MAX_AGENTS {
        agents.agents.push(agent(u8::try_from(value + 1)?, 1)?);
    }
    assert!(plan(&agents).is_ok());

    let mut maximum = PlanInput::for_replay([3; 16])?;
    for value in 0..MAX_SEGMENTS {
        let value = u8::try_from(value)?;
        maximum.segments.push(SegmentId::new(value));
        maximum.agents.push(agent(value + 1, value)?);
    }
    let mut extra_attempts = 0;
    for source in 0..MAX_SEGMENTS {
        for destination in 0..MAX_SEGMENTS {
            // A one-agent segment cannot exercise its own directed rule
            if source == destination {
                continue;
            }
            let attempts = if extra_attempts < MAX_SEGMENTS {
                extra_attempts += 1;
                2
            } else {
                1
            };
            maximum.rules.push(DirectedRule::new(
                SegmentId::new(u8::try_from(source)?),
                SegmentId::new(u8::try_from(destination)?),
                RuleExpectation::Allow,
                attempts,
            ));
        }
    }
    assert_eq!(maximum.rules.len(), MAX_SEGMENTS * (MAX_SEGMENTS - 1));
    let planned = plan(&maximum)?;
    assert_eq!(planned.probes().len(), MAX_PROBES);
    Ok(())
}

#[test]
fn same_segment_agent_pairs() -> Result<(), Box<dyn std::error::Error>> {
    let segment = SegmentId::new(7);
    let mut input = PlanInput::for_replay([0x31; 16])?;
    input.segments.push(segment);
    input.agents.extend([agent(1, 7)?, agent(2, 7)?]);
    input.rules.push(DirectedRule::new(
        segment,
        segment,
        RuleExpectation::Deny,
        1,
    ));

    let planned = plan(&input)?;

    assert_eq!(planned.probes().len(), 2);
    Ok(())
}

#[test]
fn same_segment_count_honors_limit() -> Result<(), Box<dyn std::error::Error>> {
    let segment = SegmentId::new(7);
    let mut input = PlanInput::for_replay([0x32; 16])?;
    input.segments.push(segment);
    for value in 0..MAX_AGENTS {
        input.agents.push(agent(u8::try_from(value + 1)?, 7)?);
    }
    input.rules.push(DirectedRule::new(
        segment,
        segment,
        RuleExpectation::Deny,
        1,
    ));

    let planned = plan(&input)?;

    assert_eq!(planned.probes().len(), MAX_AGENTS * (MAX_AGENTS - 1));
    Ok(())
}

#[test]
fn same_segment_cannot_bypass_limit() -> Result<(), Box<dyn std::error::Error>> {
    let segment = SegmentId::new(7);
    let mut input = PlanInput::for_replay([0x33; 16])?;
    input.segments.push(segment);
    for value in 0..MAX_AGENTS {
        input.agents.push(agent(u8::try_from(value + 1)?, 7)?);
    }
    input.rules.push(DirectedRule::new(
        segment,
        segment,
        RuleExpectation::Deny,
        2,
    ));

    assert_eq!(
        plan(&input),
        Err(PlanError::ProbeLimitExceeded {
            count: MAX_AGENTS * (MAX_AGENTS - 1) * 2,
            maximum: MAX_PROBES,
        })
    );
    Ok(())
}

#[test]
fn planner_rejects_probe_count_overflow() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = PlanInput::for_replay([4; 16])?;
    input
        .segments
        .extend([SegmentId::new(1), SegmentId::new(2)]);
    for value in 0..32 {
        input.agents.push(agent(value + 1, 1)?);
    }
    for value in 32..64 {
        input.agents.push(agent(value + 1, 2)?);
    }
    input.rules.push(DirectedRule::new(
        SegmentId::new(1),
        SegmentId::new(2),
        RuleExpectation::Allow,
        MAX_ATTEMPTS_PER_RULE,
    ));

    assert!(matches!(
        plan(&input),
        Err(PlanError::ProbeLimitExceeded { count, maximum })
            if count == 8_192 && maximum == MAX_PROBES
    ));
    Ok(())
}

#[test]
fn planner_rejects_rules_without_agents() -> Result<(), Box<dyn std::error::Error>> {
    let mut no_source = PlanInput::for_replay([5; 16])?;
    no_source
        .segments
        .extend([SegmentId::new(1), SegmentId::new(2)]);
    no_source.agents.push(agent(1, 2)?);
    no_source.rules.push(DirectedRule::new(
        SegmentId::new(1),
        SegmentId::new(2),
        RuleExpectation::Deny,
        1,
    ));
    assert!(matches!(
        plan(&no_source),
        Err(PlanError::NoSourceAgents { source, destination })
            if source == SegmentId::new(1) && destination == SegmentId::new(2)
    ));

    let mut no_destination = PlanInput::for_replay([6; 16])?;
    no_destination
        .segments
        .extend([SegmentId::new(1), SegmentId::new(2)]);
    no_destination.agents.push(agent(1, 1)?);
    no_destination.rules.push(DirectedRule::new(
        SegmentId::new(1),
        SegmentId::new(2),
        RuleExpectation::Deny,
        1,
    ));
    assert!(matches!(
        plan(&no_destination),
        Err(PlanError::NoDestinationAgents { source, destination })
            if source == SegmentId::new(1) && destination == SegmentId::new(2)
    ));
    Ok(())
}
