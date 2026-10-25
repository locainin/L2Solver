use super::support::{RUN, agent, input_with_rule, key_for};
use l2_canary::Canary;
use l2_segmentation::{PlanError, PlanInput, RuleExpectation, SegmentId, plan};
use std::{collections::BTreeSet, error::Error};

#[test]
fn rules_probes_stable_order() -> Result<(), Box<dyn Error>> {
    let mut first = PlanInput::for_replay(RUN)?;
    first
        .segments
        .extend([SegmentId::new(2), SegmentId::new(1)]);
    first
        .agents
        .extend([agent(2, 2)?, agent(1, 1)?, agent(4, 2)?, agent(3, 1)?]);
    first.rules.extend([
        l2_segmentation::DirectedRule::new(
            SegmentId::new(2),
            SegmentId::new(1),
            RuleExpectation::Allow,
            2,
        ),
        l2_segmentation::DirectedRule::new(
            SegmentId::new(1),
            SegmentId::new(2),
            RuleExpectation::Deny,
            2,
        ),
    ]);

    let mut second = PlanInput::for_replay(RUN)?;
    second
        .segments
        .extend([SegmentId::new(1), SegmentId::new(2)]);
    second
        .agents
        .extend([agent(3, 1)?, agent(4, 2)?, agent(1, 1)?, agent(2, 2)?]);
    second.rules.extend([
        l2_segmentation::DirectedRule::new(
            SegmentId::new(1),
            SegmentId::new(2),
            RuleExpectation::Deny,
            2,
        ),
        l2_segmentation::DirectedRule::new(
            SegmentId::new(2),
            SegmentId::new(1),
            RuleExpectation::Allow,
            2,
        ),
    ]);

    let first_plan = plan(&first)?;
    let second_plan = plan(&second)?;
    assert_eq!(first_plan, second_plan);
    assert_eq!(first_plan.rules().len(), 2);
    assert_eq!(first_plan.probes().len(), 16);
    assert_eq!(
        first_plan
            .probes()
            .iter()
            .map(|probe| probe.canary().map(l2_canary::Canary::sequence))
            .collect::<Result<Vec<_>, _>>()?,
        (1_u64..=16).collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn reverse_direction_is_not_inferred() -> Result<(), Box<dyn Error>> {
    let input = input_with_rule(RuleExpectation::Deny, 1)?;
    let planned = plan(&input)?;

    assert_eq!(planned.rules().len(), 1);
    assert_eq!(planned.probes().len(), 1);
    let probe = planned.probes().first().ok_or("missing forward probe")?;
    assert_eq!(probe.source_segment(), SegmentId::new(1));
    assert_eq!(probe.destination_segment(), SegmentId::new(2));
    Ok(())
}

#[test]
fn explicit_reverse_direction_is_independent() -> Result<(), Box<dyn Error>> {
    let mut input = input_with_rule(RuleExpectation::Deny, 1)?;
    input.rules.push(l2_segmentation::DirectedRule::new(
        SegmentId::new(2),
        SegmentId::new(1),
        RuleExpectation::Allow,
        1,
    ));
    let planned = plan(&input)?;

    assert_eq!(planned.rules().len(), 2);
    assert_eq!(planned.probes().len(), 2);
    let directions: Vec<_> = planned
        .probes()
        .iter()
        .map(|probe| (probe.source_segment(), probe.destination_segment()))
        .collect();
    assert_eq!(
        directions,
        vec![
            (SegmentId::new(1), SegmentId::new(2)),
            (SegmentId::new(2), SegmentId::new(1)),
        ]
    );
    Ok(())
}

#[test]
fn probes_have_unique_encodable_canaries() -> Result<(), Box<dyn Error>> {
    let mut input = input_with_rule(RuleExpectation::Allow, 4)?;
    input.agents.push(agent(3, 1)?);
    let planned = plan(&input)?;
    let mut canaries = Vec::new();
    let mut expected_attempt = 1_u8;

    for probe in planned.probes() {
        let canary = probe.canary()?;
        let key = key_for(&canary)?;
        assert_eq!(canary.run_id().into_bytes(), RUN);
        assert_eq!(l2_canary::encode(&canary, &key)?.len(), l2_canary::WIRE_LEN);
        assert_eq!(probe.attempt(), expected_attempt);
        assert!(canaries.iter().all(|previous: &Canary| previous != &canary));
        canaries.push(canary);
        expected_attempt = if expected_attempt == 4 {
            1
        } else {
            expected_attempt + 1
        };
    }
    assert_eq!(canaries.len(), 8);
    let first = planned.probes().first().ok_or("missing first probe")?;
    let mut expected_nonce = [0_u8; 16];
    expected_nonce[..8].copy_from_slice(&1_u64.to_be_bytes());
    expected_nonce[8..].copy_from_slice(b"l2seg-v1");
    assert_eq!(first.nonce(), expected_nonce);
    Ok(())
}

#[test]
fn same_segment_plans_distinct_pairs() -> Result<(), Box<dyn Error>> {
    let segment = SegmentId::new(7);
    let mut input = PlanInput::for_replay(RUN)?;
    input.segments.push(segment);
    input
        .agents
        .extend([agent(1, 7)?, agent(2, 7)?, agent(3, 7)?]);
    input.rules.push(l2_segmentation::DirectedRule::new(
        segment,
        segment,
        RuleExpectation::Allow,
        2,
    ));

    let planned = plan(&input)?;
    let pairs: BTreeSet<_> = planned
        .probes()
        .iter()
        .map(|probe| (probe.source_agent_id(), probe.destination_agent_id()))
        .collect();
    let expected_pairs = BTreeSet::from([
        (
            l2_segmentation::AgentId::new([1; 16])?,
            l2_segmentation::AgentId::new([2; 16])?,
        ),
        (
            l2_segmentation::AgentId::new([1; 16])?,
            l2_segmentation::AgentId::new([3; 16])?,
        ),
        (
            l2_segmentation::AgentId::new([2; 16])?,
            l2_segmentation::AgentId::new([1; 16])?,
        ),
        (
            l2_segmentation::AgentId::new([2; 16])?,
            l2_segmentation::AgentId::new([3; 16])?,
        ),
        (
            l2_segmentation::AgentId::new([3; 16])?,
            l2_segmentation::AgentId::new([1; 16])?,
        ),
        (
            l2_segmentation::AgentId::new([3; 16])?,
            l2_segmentation::AgentId::new([2; 16])?,
        ),
    ]);

    // Three agents produce N times N minus one directed pairs per attempt
    assert_eq!(planned.probes().len(), 3 * 2 * 2);
    assert_eq!(pairs, expected_pairs);
    assert!(
        planned
            .probes()
            .iter()
            .all(|probe| probe.source_agent_id() != probe.destination_agent_id())
    );
    Ok(())
}

#[test]
fn distinct_agent_segment_pair() -> Result<(), Box<dyn Error>> {
    let segment = SegmentId::new(7);
    for agents in [Vec::new(), vec![agent(1, 7)?]] {
        let mut input = PlanInput::for_replay(RUN)?;
        input.segments.push(segment);
        input.agents = agents;
        input.rules.push(l2_segmentation::DirectedRule::new(
            segment,
            segment,
            RuleExpectation::Deny,
            1,
        ));

        // Zero and one-agent segments are explicitly not applicable
        assert_eq!(
            plan(&input),
            Err(PlanError::NoDistinctAgentPairs { segment })
        );
    }
    Ok(())
}
