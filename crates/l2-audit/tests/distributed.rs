use l2_audit::{
    AuditError, Disposition, DistributedAgent, DistributedCanaryEvidence, DistributedPlanError,
    L2PathExpectation, Policy, PortBinding, SegmentExpectations, plan_distributed,
    plan_distributed_replay,
};
use l2_canary::{AgentKey, MIN_KEY_LEN, SessionKey, encode};
use l2_segmentation::{
    CaptureQuality, ClockDomainId, ClockStamp, ControllerEvent, EvaluationContext, Evaluator,
    EvidenceSourceId, InterfaceBindingRequest, ObservationWindowReceipt, ObservationWindowTiming,
    PacketReference, PlanError, PlannedCanaryFrame, Probe, RuleExpectation, SegmentId,
    TxCommitment, TxReceipt, TxTiming,
};
use std::collections::{BTreeMap, BTreeSet};

const fn segment() -> SegmentExpectations {
    SegmentExpectations {
        allowed_vlans: Some(BTreeSet::new()),
        priority_tagged: Disposition::Unspecified,
        untagged: Disposition::Unspecified,
        max_vlan_depth: None,
        expected_stp_bridge: None,
        lldp: Disposition::Unspecified,
        stp_endpoint: Disposition::Unspecified,
        require_8021x: None,
        protocols: BTreeMap::new(),
        isolation_from: BTreeSet::new(),
        allow_to: BTreeSet::new(),
    }
}

fn distributed_policy() -> Policy {
    let mut guest = segment();
    guest.isolation_from.insert("corporate".into());
    let mut corporate = segment();
    corporate.allow_to.insert("servers".into());
    Policy {
        schema_version: Some(2),
        segments: Some(BTreeMap::from([
            ("corporate".into(), corporate),
            ("guest".into(), guest),
            ("servers".into(), segment()),
        ])),
        ports: Some(vec![PortBinding {
            section: 0,
            index: 0,
            segment: "guest".into(),
            role: "access".into(),
        }]),
        ..Policy::default()
    }
}

fn agent(id: u8, segment: &str) -> Result<DistributedAgent, Box<dyn std::error::Error>> {
    Ok(DistributedAgent::new(
        [id; 16],
        segment,
        InterfaceBindingRequest::new(1, 2, u32::from(id), 1)?,
    )?)
}

struct ProbeExecution {
    key: SessionKey,
    wire: Vec<u8>,
    window: ObservationWindowReceipt,
    interface: InterfaceBindingRequest,
}

fn record_probe_execution(
    evaluator: &mut Evaluator,
    probe: &Probe,
) -> Result<ProbeExecution, Box<dyn std::error::Error>> {
    let canary = probe.canary()?;
    let agent_key = AgentKey::new(canary.source_agent_id(), &[0x44; MIN_KEY_LEN])?;
    let key = SessionKey::derive(&agent_key, &canary.identity())?;
    let wire = encode(&canary, &key)?;
    let mut frame = Vec::with_capacity(14 + wire.len());
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&l2_canary::ETHER_TYPE.to_be_bytes());
    frame.extend_from_slice(&wire);
    let planned_frame = PlannedCanaryFrame::from_probe(*probe, &key, &frame)?;
    let commitment = TxCommitment::from_planned_frame(&planned_frame, probe.source_interface());
    evaluator.record_commitment(commitment)?;
    evaluator.record_tx(TxReceipt::new(
        canary.run_id().into_bytes(),
        canary.sequence(),
        probe.source_interface(),
        commitment.frame_hash(),
        TxTiming::new(
            ClockStamp::new(ClockDomainId::new([0x65; 16])?, 150)?,
            ControllerEvent::new(
                canary.run_id().into_bytes(),
                canary.sequence(),
                canary.sequence() * 10 + 3,
            )?,
        ),
    )?)?;
    let interface = probe.destination_interface();
    let domain = ClockDomainId::new([0x66; 16])?;
    let run = canary.run_id().into_bytes();
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
    Ok(ProbeExecution {
        key,
        wire: wire.to_vec(),
        window,
        interface,
    })
}

fn record_probe_arrival(
    evaluator: &mut Evaluator,
    probe: &Probe,
    evidence: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let execution = record_probe_execution(evaluator, probe)?;
    let _ = evaluator.observe_wire(
        &execution.wire,
        &execution.key,
        execution.window,
        execution.interface,
        ClockStamp::new(ClockDomainId::new([0x66; 16])?, 150)?,
        PacketReference::new(EvidenceSourceId::from_bytes([0x88; 32]), evidence)?,
    )?;
    Ok(())
}

fn record_probe_absence(
    evaluator: &mut Evaluator,
    probe: &Probe,
) -> Result<(), Box<dyn std::error::Error>> {
    let execution = record_probe_execution(evaluator, probe)?;
    evaluator.record_window(execution.window)?;
    Ok(())
}

fn assert_arrival_provenance(evidence: &DistributedCanaryEvidence) {
    assert_eq!(evidence.run_id, [0x55; 16]);
    assert_eq!(evidence.probe_sequence, 2);
    assert_eq!(evidence.source_agent, [1; 16]);
    assert_eq!(evidence.receiver_agent, [2; 16]);
    assert_eq!(evidence.transmit_interface.ifindex, 1);
    assert_eq!(evidence.observation_interface.ifindex, 2);
    assert_eq!(evidence.observation_clock.domain, [0x66; 16]);
    assert_eq!(evidence.observation_clock.ticks, 150);
    assert_ne!(evidence.frame_sha256, [0; 32]);
    assert_ne!(evidence.canary_wire_sha256, [0; 32]);
    assert_eq!(evidence.window_arm_event, 21);
    assert_eq!(evidence.transmit_event, 23);
    assert_eq!(evidence.window_close_event, 25);
    assert_eq!(evidence.window_complete_event, 27);
}

#[test]
fn ordinary_plan_generates_run_identity() -> Result<(), Box<dyn std::error::Error>> {
    let agents = [
        agent(1, "guest")?,
        agent(2, "corporate")?,
        agent(3, "servers")?,
    ];
    let planned = plan_distributed(&distributed_policy(), &agents, 1)?;

    assert_ne!(planned.plan().run_id(), &[0; 16]);
    Ok(())
}

#[test]
fn plan_translates_explicit_directed_paths() -> Result<(), Box<dyn std::error::Error>> {
    let agents = [
        agent(1, "guest")?,
        agent(2, "corporate")?,
        agent(3, "servers")?,
    ];
    let planned = plan_distributed_replay(&distributed_policy(), [0x55; 16], &agents, 3)?;

    assert_eq!(planned.plan().rules().len(), 2);
    assert_eq!(planned.plan().probes().len(), 6);
    assert_eq!(planned.segment_name(SegmentId::new(1)), Some("corporate"));
    assert_eq!(planned.segment_name(SegmentId::new(2)), Some("guest"));
    assert_eq!(planned.segment_name(SegmentId::new(3)), Some("servers"));
    let directions: Vec<_> = planned
        .plan()
        .rules()
        .iter()
        .map(|rule| {
            (
                planned.segment_name(rule.source()),
                planned.segment_name(rule.destination()),
                rule.expectation(),
            )
        })
        .collect();
    assert_eq!(
        directions,
        vec![
            (Some("corporate"), Some("servers"), RuleExpectation::Allow),
            (Some("guest"), Some("corporate"), RuleExpectation::Deny),
        ]
    );
    assert!(
        directions
            .iter()
            .all(|(source, destination, _)| *source != Some("corporate")
                || *destination != Some("guest"))
    );
    Ok(())
}

#[test]
fn planner_segment_limit() {
    let mut segments = BTreeMap::new();
    for index in 0..64 {
        segments.insert(format!("segment-{index:02}"), segment());
    }
    let valid = Policy {
        schema_version: Some(2),
        segments: Some(segments.clone()),
        ports: Some(Vec::new()),
        ..Policy::default()
    };
    assert!(plan_distributed_replay(&valid, [0x66; 16], &[], 1).is_ok());

    segments.insert(String::from("segment-64"), segment());
    let too_many = Policy {
        segments: Some(segments),
        ..valid
    };
    assert!(matches!(
        plan_distributed_replay(&too_many, [0x66; 16], &[], 1),
        Err(DistributedPlanError::Plan(
            l2_segmentation::PlanError::SegmentLimitExceeded {
                count: 65,
                maximum: 64
            }
        ))
    ));
}

#[test]
fn plan_rejects_missing_agents_segments() -> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        DistributedAgent::new([0; 16], "guest", InterfaceBindingRequest::new(1, 2, 1, 1)?,),
        Err(DistributedPlanError::InvalidAgentId)
    ));
    assert!(matches!(
        DistributedAgent::new(
            [1; 16],
            "../guest",
            InterfaceBindingRequest::new(1, 2, 1, 1)?,
        ),
        Err(DistributedPlanError::InvalidAgentSegment)
    ));
    let unknown = agent(1, "unknown")?;
    assert!(matches!(
        plan_distributed_replay(&distributed_policy(), [0x55; 16], &[unknown], 1),
        Err(DistributedPlanError::UnknownAgentSegment { .. })
    ));
    let guest_only = agent(1, "guest")?;
    assert!(matches!(
        plan_distributed_replay(&distributed_policy(), [0x55; 16], &[guest_only], 1),
        Err(DistributedPlanError::Plan(_))
    ));
    assert!(matches!(
        plan_distributed_replay(&distributed_policy(), [0; 16], &[], 1),
        Err(DistributedPlanError::RunId(
            l2_canary::RunIdError::ReservedZero
        ))
    ));
    Ok(())
}

#[test]
fn agent_accessors_errors_stable() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = agent(9, "guest")?;
    assert_eq!(endpoint.id(), &[9; 16]);
    assert_eq!(endpoint.segment(), "guest");
    assert_eq!(endpoint.interface().ifindex(), 9);
    assert_eq!(
        l2_audit::DistributedResultError.to_string(),
        "distributed evaluation does not match the supplied plan"
    );
    assert_eq!(
        DistributedPlanError::RunId(l2_canary::RunIdError::ReservedZero).to_string(),
        "distributed run identity is invalid: assessment run ID must not be all zeroes"
    );
    Ok(())
}

#[test]
fn policy_conflicting_deny_paths() {
    let mut policy = distributed_policy();
    if let Some(guest) = policy
        .segments
        .as_mut()
        .and_then(|segments| segments.get_mut("guest"))
    {
        guest.allow_to.insert("corporate".into());
    }
    assert!(policy.validate().is_err());
}

#[test]
fn path_expectation_names_are_stable() {
    assert_eq!(L2PathExpectation::Allow.as_str(), "allow");
    assert_eq!(L2PathExpectation::Deny.as_str(), "deny");
    assert_eq!(SegmentId::new(1).get(), 1);
}

#[test]
fn distributed_plan_errors_nested_causes() {
    let policy_error = DistributedPlanError::InvalidPolicy(AuditError::Policy("bad policy"));
    assert!(std::error::Error::source(&policy_error).is_some());

    let plan_error = DistributedPlanError::Plan(PlanError::SequenceOverflow);
    assert!(std::error::Error::source(&plan_error).is_some());
    assert!(
        std::error::Error::source(&DistributedPlanError::RunId(
            l2_canary::RunIdError::ReservedZero
        ))
        .is_some()
    );
}

#[test]
fn separates_pass_results_from_findings() -> Result<(), Box<dyn std::error::Error>> {
    let agents = [
        agent(1, "guest")?,
        agent(2, "corporate")?,
        agent(3, "servers")?,
    ];
    let planned = plan_distributed_replay(&distributed_policy(), [0x55; 16], &agents, 1)?;
    let mut evaluator = Evaluator::new(planned.plan());

    for probe in planned.plan().probes() {
        let direction = (
            planned.segment_name(probe.source_segment()),
            planned.segment_name(probe.destination_segment()),
        );
        if matches!(
            direction,
            (Some("guest"), Some("corporate")) | (Some("corporate"), Some("servers"))
        ) {
            let evidence = if direction == (Some("guest"), Some("corporate")) {
                501
            } else {
                502
            };
            record_probe_arrival(&mut evaluator, probe, evidence)?;
        }
    }
    let evaluation = evaluator.evaluate(&EvaluationContext::healthy());
    let assessment = l2_audit::assess_distributed(&planned, &evaluation)?;

    assert_eq!(assessment.results.len(), 2);
    assert!(assessment.results.iter().any(|result| {
        result.source_segment == "corporate"
            && result.destination_segment == "servers"
            && result.verdict == l2_audit::Verdict::Pass
            && result
                .evidence
                .first()
                .is_some_and(|evidence| evidence.packet_sequence == 502)
    }));
    assert!(assessment.results.iter().any(|result| {
        result.source_segment == "guest"
            && result.destination_segment == "corporate"
            && result.verdict == l2_audit::Verdict::Fail
            && result
                .evidence
                .first()
                .is_some_and(|evidence| evidence.packet_sequence == 501)
    }));
    assert_eq!(assessment.findings.len(), 1);
    let finding = assessment.findings.first().ok_or("missing leak finding")?;
    assert_eq!(finding.check_id, "SEG-001");
    assert_eq!(finding.evidence_packets, [501]);
    assert_eq!(
        finding.source_interfaces,
        ["netns=1:2,ifindex=2,datalink=1"]
    );
    assert!(finding.expected.contains("guest -> corporate"));
    assert!(finding.observed.contains("1/1 authenticated canaries"));

    let failed_path = assessment
        .results
        .iter()
        .find(|result| result.verdict == l2_audit::Verdict::Fail)
        .ok_or("missing failed path")?;
    let evidence = failed_path
        .evidence
        .first()
        .ok_or("missing structured evidence")?;
    assert_arrival_provenance(evidence);

    let serialized = serde_json::to_value(failed_path)?;
    assert_eq!(
        serialized.pointer("/evidence/0/packet_sequence"),
        Some(&serde_json::json!(501))
    );
    assert_eq!(
        serialized.pointer("/evidence/0/packet_source"),
        Some(&serde_json::json!(
            "sha256:8888888888888888888888888888888888888888888888888888888888888888"
        ))
    );
    assert!(serialized.get("evidence_packets").is_none());
    Ok(())
}

#[test]
fn absence_inconclusive_incomplete_capture() -> Result<(), Box<dyn std::error::Error>> {
    let agents = [
        agent(1, "guest")?,
        agent(2, "corporate")?,
        agent(3, "servers")?,
    ];
    let planned = plan_distributed_replay(&distributed_policy(), [0x55; 16], &agents, 1)?;
    let evaluation = Evaluator::new(planned.plan()).evaluate(&EvaluationContext::new(
        true,
        true,
        CaptureQuality::Incomplete,
        false,
    ));

    let assessment = l2_audit::assess_distributed(&planned, &evaluation)?;

    assert!(assessment.findings.is_empty());
    assert!(
        assessment
            .results
            .iter()
            .all(|result| result.verdict == l2_audit::Verdict::Inconclusive)
    );
    Ok(())
}

#[test]
fn deny_pass_exact_absence_provenance() -> Result<(), Box<dyn std::error::Error>> {
    let agents = [
        agent(1, "guest")?,
        agent(2, "corporate")?,
        agent(3, "servers")?,
    ];
    let planned = plan_distributed_replay(&distributed_policy(), [0x55; 16], &agents, 1)?;
    let mut evaluator = Evaluator::new(planned.plan());
    for probe in planned.plan().probes().iter().filter(|probe| {
        planned.segment_name(probe.source_segment()) == Some("guest")
            && planned.segment_name(probe.destination_segment()) == Some("corporate")
    }) {
        record_probe_absence(&mut evaluator, probe)?;
    }

    let evaluation = evaluator.evaluate(&EvaluationContext::healthy());
    let assessment = l2_audit::assess_distributed(&planned, &evaluation)?;
    let denied = assessment
        .results
        .iter()
        .find(|result| result.expectation == L2PathExpectation::Deny)
        .ok_or("missing deny result")?;

    assert_eq!(denied.verdict, l2_audit::Verdict::Pass);
    let evidence = denied
        .absence_evidence
        .first()
        .ok_or("missing absence evidence")?;
    assert_eq!(evidence.run_id, [0x55; 16]);
    assert_eq!(evidence.source_agent, [1; 16]);
    assert_eq!(evidence.receiver_agent, [2; 16]);
    assert_eq!(evidence.transmit_interface.ifindex, 1);
    assert_eq!(evidence.observation_interface.ifindex, 2);
    assert_eq!(evidence.window_arm_event, 21);
    assert_eq!(evidence.transmit_event, 23);
    assert_eq!(evidence.window_close_event, 25);
    assert_eq!(evidence.window_complete_event, 27);
    assert_ne!(evidence.frame_sha256, [0; 32]);
    Ok(())
}

#[test]
fn evaluation_rejects_other_plan_results() -> Result<(), Box<dyn std::error::Error>> {
    let agents = [
        agent(1, "guest")?,
        agent(2, "corporate")?,
        agent(3, "servers")?,
    ];
    let planned = plan_distributed_replay(&distributed_policy(), [0x55; 16], &agents, 1)?;
    let other = plan_distributed_replay(&distributed_policy(), [0x66; 16], &agents, 2)?;
    let evaluation = Evaluator::new(other.plan()).evaluate(&EvaluationContext::healthy());

    assert!(l2_audit::assess_distributed(&planned, &evaluation).is_err());
    Ok(())
}
