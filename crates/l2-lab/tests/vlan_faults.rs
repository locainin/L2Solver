mod support;

use std::error::Error;

use l2_canary::AgentId;
use l2_lab::{
    BridgeMode, Cancellation, ObservationMode, RunOptions, VirtualEndpoint, VirtualLab, VlanId,
};
use l2_onpath::{Budget, MAX_BYTE_BUDGET};
use l2_scenario::{MAX_STIMULI, StopReason};
use l2_segmentation::{
    Agent, DirectedRule, EvaluationStatus, PlanInput, RuleExpectation, SegmentId,
};

use support::{SYNTHETIC_KEY, binding, budget, scenario};

const CAPTURE_MARKER: &[u8] = b"l2solver-virtual-capture-v1\0";

#[test]
fn serialized_capture_contains_the_documented_records() -> Result<(), Box<dyn Error>> {
    let (plan, endpoints) = scenario()?;
    let lab = VirtualLab::new(&plan, &endpoints, BridgeMode::VlanAware)?;
    let run = lab.run(&SYNTHETIC_KEY, budget()?, RunOptions::default())?;
    let capture = run.capture();
    let bytes = capture.bytes()?;
    let records = bytes
        .strip_prefix(CAPTURE_MARKER)
        .ok_or("virtual capture marker is missing")?;
    let frame_len = 14 + l2_canary::WIRE_LEN;
    let record_len = 8 + l2_canary::ID_LEN + 8 + frame_len;
    let chunks = records.chunks_exact(record_len);
    assert!(chunks.remainder().is_empty());
    assert_eq!(chunks.len(), capture.records().len());
    assert!(!capture.records().is_empty());

    // Decode the documented stream independently from the capture serializer
    for (record, chunk) in capture.records().iter().zip(chunks) {
        let sequence = u64::from_be_bytes(chunk.get(..8).ok_or("missing sequence")?.try_into()?);
        let receiver = chunk.get(8..24).ok_or("missing receiver")?;
        let encoded_len =
            u64::from_be_bytes(chunk.get(24..32).ok_or("missing length")?.try_into()?);
        let frame = chunk.get(32..).ok_or("missing frame")?;
        assert_eq!(sequence, record.sequence());
        assert_eq!(receiver, record.receiver().as_bytes());
        assert_eq!(encoded_len, u64::try_from(frame_len)?);
        assert_eq!(frame, record.frame());
    }
    Ok(())
}

#[test]
fn empty_capture_keeps_the_virtual_format_marker() -> Result<(), Box<dyn Error>> {
    let (plan, endpoints) = scenario()?;
    let lab = VirtualLab::new(&plan, &endpoints, BridgeMode::VlanAware)?;
    let run = lab.run(
        &SYNTHETIC_KEY,
        budget()?,
        RunOptions::new(ObservationMode::Unavailable, Cancellation::Never),
    )?;
    assert!(run.capture().records().is_empty());
    assert_eq!(run.capture().bytes()?.as_slice(), CAPTURE_MARKER);
    assert_eq!(
        run.evaluation().overall_status(),
        EvaluationStatus::Inconclusive
    );
    Ok(())
}

#[test]
fn maximum_probe_plan_is_admitted_before_immediate_cancellation() -> Result<(), Box<dyn Error>> {
    let source = SegmentId::new(1);
    let destination = SegmentId::new(2);
    let mut input = PlanInput::for_replay([0x22; 16])?;
    input.segments.extend([source, destination]);
    input.rules.push(DirectedRule::new(
        source,
        destination,
        RuleExpectation::Deny,
        4,
    ));
    let mut endpoints = Vec::new();
    for host in 1_u8..=64 {
        let segment = if host <= 32 { source } else { destination };
        let agent = Agent::new(
            AgentId::new([host; 16])?,
            segment,
            binding(u32::from(host))?,
        );
        input.agents.push(agent);
        endpoints.push(VirtualEndpoint::new(
            agent.id(),
            agent.interface(),
            [2, 0, 0, 0, 0, host],
            VlanId::new(if segment == source { 10 } else { 20 })?,
        )?);
    }
    let plan = input.plan()?;
    let packets = u64::try_from(MAX_STIMULI)?;
    assert_eq!(plan.probes().len(), MAX_STIMULI);
    let lab = VirtualLab::new(&plan, &endpoints, BridgeMode::VlanAware)?;
    let run = lab.run(
        &SYNTHETIC_KEY,
        Budget::new(packets, MAX_BYTE_BUDGET, packets)?,
        RunOptions::new(ObservationMode::Healthy, Cancellation::After(0)),
    )?;

    // Admission is inclusive even when cancellation stops the first dispatch
    assert_eq!(run.execution().stop_reason(), StopReason::Cancelled);
    assert_eq!(run.execution().packets(), 0);
    assert_eq!(
        run.evaluation().overall_status(),
        EvaluationStatus::Inconclusive
    );
    Ok(())
}

#[test]
fn cancellation_at_or_after_completion_keeps_the_exhausted_result() -> Result<(), Box<dyn Error>> {
    let (plan, endpoints) = scenario()?;
    let lab = VirtualLab::new(&plan, &endpoints, BridgeMode::VlanAware)?;
    let count = u64::try_from(plan.probes().len())?;
    for after in [count, count + 1] {
        let run = lab.run(
            &SYNTHETIC_KEY,
            budget()?,
            RunOptions::new(ObservationMode::Healthy, Cancellation::After(after)),
        )?;
        assert_eq!(run.execution().stop_reason(), StopReason::Exhausted);
        assert_eq!(run.execution().packets(), count);
        assert_eq!(run.evaluation().overall_status(), EvaluationStatus::Pass);
    }
    Ok(())
}

#[test]
fn cancelled_deny_rules_do_not_pass_after_partial_observation() -> Result<(), Box<dyn Error>> {
    let (plan, endpoints) = scenario()?;
    let lab = VirtualLab::new(&plan, &endpoints, BridgeMode::VlanAware)?;
    let count = u64::try_from(plan.probes().len())?;
    for after in 0..count {
        let run = lab.run(
            &SYNTHETIC_KEY,
            budget()?,
            RunOptions::new(ObservationMode::Healthy, Cancellation::After(after)),
        )?;
        assert_eq!(run.execution().stop_reason(), StopReason::Cancelled);
        assert_eq!(run.execution().packets(), after);
        assert_eq!(
            run.evaluation().overall_status(),
            EvaluationStatus::Inconclusive
        );
        for rule in run.evaluation().results() {
            if rule.expectation() == RuleExpectation::Deny {
                // Completed early windows do not turn a cancelled run into a pass
                assert_eq!(rule.status(), EvaluationStatus::Inconclusive);
            }
        }
    }
    Ok(())
}

#[test]
fn broken_allowed_path_cannot_be_reported_as_a_pass() -> Result<(), Box<dyn Error>> {
    let (plan, mut endpoints) = scenario()?;
    let endpoint = endpoints.get_mut(1).ok_or("missing fixture endpoint")?;
    *endpoint = VirtualEndpoint::new(
        endpoint.agent_id(),
        endpoint.interface(),
        endpoint.mac(),
        VlanId::new(11)?,
    )?;
    let lab = VirtualLab::new(&plan, &endpoints, BridgeMode::VlanAware)?;
    let run = lab.run(&SYNTHETIC_KEY, budget()?, RunOptions::default())?;
    let allow = run
        .evaluation()
        .results()
        .iter()
        .find(|rule| rule.expectation() == RuleExpectation::Allow)
        .ok_or("missing allow rule")?;

    // A missing allowed arrival is insufficient evidence rather than a pass
    assert_eq!(allow.status(), EvaluationStatus::Inconclusive);
    assert_eq!(allow.matching_receipts(), 0);
    assert_eq!(
        run.evaluation().overall_status(),
        EvaluationStatus::Inconclusive
    );
    Ok(())
}
