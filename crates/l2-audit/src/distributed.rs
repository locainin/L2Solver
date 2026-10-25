//! Pure translation from named assessment policy to authenticated probe plans

mod evidence;

pub use evidence::{
    DistributedCanaryAbsenceEvidence, DistributedCanaryEvidence, DistributedClockStamp,
    DistributedInterfaceBinding,
};

use crate::{AuditError, Finding, Policy, Severity, Verdict};
use l2_canary::{RunId, RunIdError};
use l2_segmentation::{
    Agent, AgentId, DirectedRule, EvaluationReport, EvaluationStatus, InterfaceBindingRequest,
    MAX_SEGMENTS, Plan, PlanError, PlanInput, RuleExpectation, SegmentId, plan,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

const ID_LENGTH: usize = 16;
const MAX_SEGMENT_LABEL_BYTES: usize = 64;

/// Expected result for one explicitly directed Layer-2 path
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum L2PathExpectation {
    Allow,
    Deny,
}

impl L2PathExpectation {
    /// Stable policy and report label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    const fn rule(self) -> RuleExpectation {
        match self {
            Self::Allow => RuleExpectation::Allow,
            Self::Deny => RuleExpectation::Deny,
        }
    }

    const fn from_rule(expectation: RuleExpectation) -> Self {
        match expectation {
            RuleExpectation::Allow => Self::Allow,
            RuleExpectation::Deny => Self::Deny,
        }
    }
}

/// One directed distributed result kept outside the passive finding collection
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DistributedPathResult {
    pub check_id: String,
    pub source_segment: String,
    pub destination_segment: String,
    pub expectation: L2PathExpectation,
    pub verdict: Verdict,
    pub planned_attempts: usize,
    pub matching_receipts: usize,
    pub missing_attempts: usize,
    pub evidence: Vec<DistributedCanaryEvidence>,
    pub absence_evidence: Vec<DistributedCanaryAbsenceEvidence>,
    pub limitations: Vec<String>,
}

/// Complete result of translating authenticated canary receipts into audit data
#[derive(Debug, Serialize)]
pub struct DistributedAssessment {
    pub results: Vec<DistributedPathResult>,
    /// Only demonstrated policy failures become report findings
    pub findings: Vec<Finding>,
}

/// A controlled endpoint assigned to one named policy segment
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedAgent {
    id: [u8; ID_LENGTH],
    segment: String,
    interface: InterfaceBindingRequest,
}

impl DistributedAgent {
    /// Construct a checked controlled endpoint identity
    ///
    /// # Errors
    /// Rejects an all-zero identity or an unsafe segment label
    pub fn new(
        id: [u8; ID_LENGTH],
        segment: impl Into<String>,
        interface: InterfaceBindingRequest,
    ) -> Result<Self, DistributedPlanError> {
        if id == [0; ID_LENGTH] {
            return Err(DistributedPlanError::InvalidAgentId);
        }
        let segment = segment.into();
        if !valid_label(&segment) {
            return Err(DistributedPlanError::InvalidAgentSegment);
        }
        Ok(Self {
            id,
            segment,
            interface,
        })
    }

    /// Return the authenticated agent identity bytes
    #[must_use]
    pub const fn id(&self) -> &[u8; ID_LENGTH] {
        &self.id
    }

    /// Return the named policy segment
    #[must_use]
    pub fn segment(&self) -> &str {
        &self.segment
    }

    /// Return the exact namespace and interface attachment for this endpoint
    #[must_use]
    pub const fn interface(&self) -> InterfaceBindingRequest {
        self.interface
    }
}

/// A validated canary plan plus its stable name mapping
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedPlan {
    plan: Plan,
    segment_names: BTreeMap<SegmentId, String>,
}

impl DistributedPlan {
    /// Return the authority-free canary plan
    #[must_use]
    pub const fn plan(&self) -> &Plan {
        &self.plan
    }

    /// Resolve a numeric planner segment back to its policy label
    #[must_use]
    pub fn segment_name(&self, segment: SegmentId) -> Option<&str> {
        self.segment_names.get(&segment).map(String::as_str)
    }
}

/// Validation failures before any canary can be emitted
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DistributedPlanError {
    InvalidPolicy(AuditError),
    VersionedPolicyRequired,
    RunId(RunIdError),
    InvalidAgentId,
    InvalidAgentSegment,
    UnknownAgentSegment { segment: String },
    Plan(PlanError),
}

/// Evaluation data did not originate from the supplied immutable plan
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DistributedResultError;

impl fmt::Display for DistributedResultError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("distributed evaluation does not match the supplied plan")
    }
}

impl std::error::Error for DistributedResultError {}

impl fmt::Display for DistributedPlanError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(error) => write!(output, "distributed policy is invalid: {error}"),
            Self::VersionedPolicyRequired => {
                output.write_str("distributed planning requires a versioned segment policy")
            }
            Self::RunId(error) => write!(output, "distributed run identity is invalid: {error}"),
            Self::InvalidAgentId => output.write_str("distributed agent ID must not be all zeroes"),
            Self::InvalidAgentSegment => {
                output.write_str("agent segment must use 1..=64 safe ASCII bytes")
            }
            Self::UnknownAgentSegment { segment } => {
                write!(output, "agent references unknown segment {segment}")
            }
            Self::Plan(error) => write!(output, "distributed plan is invalid: {error}"),
        }
    }
}

impl std::error::Error for DistributedPlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPolicy(error) => Some(error),
            Self::RunId(error) => Some(error),
            Self::Plan(error) => Some(error),
            Self::VersionedPolicyRequired
            | Self::InvalidAgentId
            | Self::InvalidAgentSegment
            | Self::UnknownAgentSegment { .. } => None,
        }
    }
}

/// Build a bounded directed canary plan without opening interfaces or transmitting
///
/// `isolation_from` creates a deny path from the owning segment to each target
/// and `allow_to` creates an allow path in the same explicit direction. Reverse
/// paths are never inferred.
///
/// # Errors
/// Rejects invalid policy, unknown agents, unsafe IDs, and segmentation bounds
pub fn plan_distributed(
    policy: &Policy,
    agents: &[DistributedAgent],
    attempts: u8,
) -> Result<DistributedPlan, DistributedPlanError> {
    let run_id = RunId::generate().map_err(DistributedPlanError::RunId)?;
    plan_distributed_for_run(policy, run_id, agents, attempts)
}

/// Rebuild a distributed plan from an authoritative recorded run identity
///
/// # Errors
///
/// Rejects invalid recorded identities and all ordinary planning errors
pub fn plan_distributed_replay(
    policy: &Policy,
    run_id: [u8; ID_LENGTH],
    agents: &[DistributedAgent],
    attempts: u8,
) -> Result<DistributedPlan, DistributedPlanError> {
    let run_id = RunId::from_recorded(run_id).map_err(DistributedPlanError::RunId)?;
    plan_distributed_for_run(policy, run_id, agents, attempts)
}

fn plan_distributed_for_run(
    policy: &Policy,
    run_id: RunId,
    agents: &[DistributedAgent],
    attempts: u8,
) -> Result<DistributedPlan, DistributedPlanError> {
    policy
        .validate()
        .map_err(DistributedPlanError::InvalidPolicy)?;
    let Some(segments) = policy.segments.as_ref() else {
        return Err(DistributedPlanError::VersionedPolicyRequired);
    };
    if segments.len() > MAX_SEGMENTS {
        return Err(DistributedPlanError::Plan(
            PlanError::SegmentLimitExceeded {
                count: segments.len(),
                maximum: MAX_SEGMENTS,
            },
        ));
    }

    let mut by_name = BTreeMap::new();
    let mut segment_names = BTreeMap::new();
    for (offset, name) in segments.keys().enumerate() {
        let value = u8::try_from(offset + 1).map_err(|_| {
            DistributedPlanError::Plan(PlanError::SegmentLimitExceeded {
                count: segments.len(),
                maximum: MAX_SEGMENTS,
            })
        })?;
        let id = SegmentId::new(value);
        by_name.insert(name.as_str(), id);
        segment_names.insert(id, name.clone());
    }

    let mut input = PlanInput::from_run_id(run_id);
    input.segments.extend(segment_names.keys().copied());
    for agent in agents {
        let Some(segment) = by_name.get(agent.segment.as_str()).copied() else {
            return Err(DistributedPlanError::UnknownAgentSegment {
                segment: agent.segment.clone(),
            });
        };
        let agent_id = AgentId::new(agent.id).map_err(|_| DistributedPlanError::InvalidAgentId)?;
        input
            .agents
            .push(Agent::new(agent_id, segment, agent.interface));
    }
    for (source_name, expectations) in segments {
        let source = by_name
            .get(source_name.as_str())
            .copied()
            .ok_or(DistributedPlanError::VersionedPolicyRequired)?;
        append_rules(
            &mut input,
            source,
            &expectations.isolation_from,
            &by_name,
            L2PathExpectation::Deny,
            attempts,
        )?;
        append_rules(
            &mut input,
            source,
            &expectations.allow_to,
            &by_name,
            L2PathExpectation::Allow,
            attempts,
        )?;
    }

    let plan = plan(&input).map_err(DistributedPlanError::Plan)?;
    Ok(DistributedPlan {
        plan,
        segment_names,
    })
}

/// Convert a complete authenticated canary evaluation into named audit results
///
/// Pass and inconclusive outcomes remain check results. Only directly observed
/// policy violations become findings.
///
/// # Errors
/// Rejects evaluation data produced from a different immutable plan
pub fn assess_distributed(
    plan: &DistributedPlan,
    evaluation: &EvaluationReport,
) -> Result<DistributedAssessment, DistributedResultError> {
    if plan.plan() != evaluation.plan() {
        return Err(DistributedResultError);
    }
    let mut results = Vec::with_capacity(evaluation.results().len());
    let mut findings = Vec::new();
    for result in evaluation.results() {
        let source = plan
            .segment_name(result.source())
            .ok_or(DistributedResultError)?;
        let destination = plan
            .segment_name(result.destination())
            .ok_or(DistributedResultError)?;
        let expectation = L2PathExpectation::from_rule(result.expectation());
        let verdict = evaluation_verdict(result.status());
        let path_result = DistributedPathResult {
            check_id: "SEG-001".into(),
            source_segment: source.into(),
            destination_segment: destination.into(),
            expectation,
            verdict,
            planned_attempts: result.planned_attempts(),
            matching_receipts: result.matching_receipts(),
            missing_attempts: result.missing_attempts(),
            evidence: result
                .evidence()
                .iter()
                .copied()
                .map(DistributedCanaryEvidence::from)
                .collect(),
            absence_evidence: result
                .absence_evidence()
                .iter()
                .copied()
                .map(DistributedCanaryAbsenceEvidence::from)
                .collect(),
            limitations: result.limitations().to_vec(),
        };
        if verdict == Verdict::Fail {
            findings.push(distributed_finding(&path_result));
        }
        results.push(path_result);
    }
    Ok(DistributedAssessment { results, findings })
}

const fn evaluation_verdict(status: EvaluationStatus) -> Verdict {
    match status {
        EvaluationStatus::Pass => Verdict::Pass,
        EvaluationStatus::Fail => Verdict::Fail,
        EvaluationStatus::Inconclusive => Verdict::Inconclusive,
    }
}

fn distributed_finding(result: &DistributedPathResult) -> Finding {
    let evidence_packets = result
        .evidence
        .iter()
        .map(|evidence| evidence.packet_sequence)
        .collect();
    let source_interfaces = result
        .evidence
        .iter()
        .map(|evidence| evidence.observation_interface.report_label())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Finding {
        check_id: result.check_id.clone(),
        verdict: Verdict::Fail,
        severity: Severity::High,
        title: "Layer-2 segmentation policy failed".into(),
        expected: format!(
            "{} -> {} must be isolated for the tested Layer-2 canaries",
            result.source_segment, result.destination_segment
        ),
        observed: format!(
            "{}/{} authenticated canaries crossed the prohibited directed path",
            result.matching_receipts, result.planned_attempts
        ),
        evidence_packets,
        source_interfaces,
        remediation: "Enforce the intended VLAN, private-port, or client-isolation boundary and repeat the directed test".into(),
        limitations: result.limitations.clone(),
    }
}

fn append_rules(
    input: &mut PlanInput,
    source: SegmentId,
    targets: &std::collections::BTreeSet<String>,
    by_name: &BTreeMap<&str, SegmentId>,
    expectation: L2PathExpectation,
    attempts: u8,
) -> Result<(), DistributedPlanError> {
    for target_name in targets {
        let destination = by_name
            .get(target_name.as_str())
            .copied()
            .ok_or(DistributedPlanError::VersionedPolicyRequired)?;
        input.rules.push(DirectedRule::new(
            source,
            destination,
            expectation.rule(),
            attempts,
        ));
    }
    Ok(())
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SEGMENT_LABEL_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
