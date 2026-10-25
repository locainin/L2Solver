//! Passive assessment output keeps surfaces, assertions, and coverage separate

use crate::{
    AuditError, CheckCategory, Finding, InterfaceObservation, NetworkModel, Policy, Quality,
    Severity, SourceLabelMap, build_network_model, checks,
    exposures::build_exposures,
    planner::{
        CheckPlan, MAX_FINDINGS, PlannerInput, plan_passive, plan_passive_with_source_labels,
    },
    role::{PortRoleInference, infer_port_roles},
};
use serde::Serialize;
use std::collections::BTreeMap;

/// An observed control-plane surface with informational severity
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Exposure {
    pub check_id: String,
    pub severity: Severity,
    pub title: String,
    pub observed: String,
    pub evidence_packets: Vec<u64>,
    pub source_interfaces: Vec<String>,
    pub limitations: Vec<String>,
}

/// The state of one check in the current assessment
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Tested,
    NotTested,
    NotApplicable,
}

/// A coverage entry is a planning statement rather than a security finding
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CoverageEntry {
    pub check_id: String,
    pub status: CoverageStatus,
    pub reason: String,
}

/// Aggregate check completion for one security domain
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CoverageMetric {
    pub category: CheckCategory,
    pub tested: usize,
    pub not_tested: usize,
    pub not_applicable: usize,
    /// Tested checks divided by applicable checks, rounded down
    pub percent: Option<u8>,
}

/// Distinct passive assessment results for one captured scope
#[derive(Debug, Serialize)]
pub struct AssessmentResult {
    pub port_roles: Vec<PortRoleInference>,
    pub network_model: NetworkModel,
    pub exposures: Vec<Exposure>,
    pub findings: Vec<Finding>,
    pub coverage: Vec<CoverageEntry>,
    pub coverage_summary: Vec<CoverageMetric>,
    pub plan: CheckPlan,
}

/// Evaluate policy assertions, informational surfaces, and coverage without transmission
///
/// # Errors
/// Returns an error when the policy is invalid
pub fn assess(
    interfaces: &[InterfaceObservation],
    policy: &Policy,
    quality: &Quality,
) -> Result<AssessmentResult, AuditError> {
    let input = PlannerInput::from_interfaces(interfaces);
    assess_with_input(interfaces, policy, quality, &input)
}

/// Evaluate a passive assessment with protocol fingerprints supplied by discovery
///
/// # Errors
/// Returns an error when the policy is invalid
pub fn assess_with_input(
    interfaces: &[InterfaceObservation],
    policy: &Policy,
    quality: &Quality,
    input: &PlannerInput,
) -> Result<AssessmentResult, AuditError> {
    policy.validate()?;
    let mut findings = checks::evaluate_policy(interfaces, policy);
    findings.truncate(MAX_FINDINGS);
    let plan = plan_passive(input, policy);
    Ok(build_assessment(interfaces, quality, findings, plan))
}

/// Evaluate a passive assessment after resolving policy sources by stable labels
///
/// # Errors
/// Returns a source-mapping error before policy assertions or planning run when
/// a schema-three policy cannot be resolved for the observed interfaces
pub fn assess_with_source_labels(
    interfaces: &[InterfaceObservation],
    policy: &Policy,
    quality: &Quality,
    labels: &SourceLabelMap,
) -> Result<AssessmentResult, AuditError> {
    let input = PlannerInput::from_interfaces(interfaces);
    assess_with_input_and_source_labels(interfaces, policy, quality, &input, labels)
}

/// Evaluate a passive assessment with discovery input and stable source labels
///
/// # Errors
/// Returns an invalid-policy or source-mapping error before evaluation when the
/// supplied policy cannot be applied to the capture interfaces
pub fn assess_with_input_and_source_labels(
    interfaces: &[InterfaceObservation],
    policy: &Policy,
    quality: &Quality,
    input: &PlannerInput,
    labels: &SourceLabelMap,
) -> Result<AssessmentResult, AuditError> {
    // Plan first so policy and source validation precede finding evaluation
    let plan = plan_passive_with_source_labels(input, policy, labels)?;
    let mut findings = checks::evaluate_policy_with_source_labels(interfaces, policy, labels)?;
    findings.truncate(MAX_FINDINGS);
    Ok(build_assessment(interfaces, quality, findings, plan))
}

fn build_assessment(
    interfaces: &[InterfaceObservation],
    quality: &Quality,
    findings: Vec<Finding>,
    plan: CheckPlan,
) -> AssessmentResult {
    let port_roles = infer_port_roles(interfaces);
    let network_model = build_network_model(interfaces);
    let exposures = build_exposures(interfaces, &network_model);
    let coverage = coverage(&plan, quality);
    let coverage_summary = summarize_coverage(&plan);
    AssessmentResult {
        port_roles,
        network_model,
        exposures,
        findings,
        coverage,
        coverage_summary,
        plan,
    }
}

fn summarize_coverage(plan: &CheckPlan) -> Vec<CoverageMetric> {
    let mut categories = BTreeMap::new();
    for entry in &plan.entries {
        let metric = categories
            .entry(entry.category)
            .or_insert_with(|| CoverageMetric {
                category: entry.category,
                tested: 0,
                not_tested: 0,
                not_applicable: 0,
                percent: None,
            });
        match entry.coverage {
            CoverageStatus::Tested => metric.tested += 1,
            CoverageStatus::NotTested => metric.not_tested += 1,
            CoverageStatus::NotApplicable => metric.not_applicable += 1,
        }
    }
    for metric in categories.values_mut() {
        let applicable = metric.tested + metric.not_tested;
        metric.percent = metric
            .tested
            .checked_mul(100)
            .and_then(|value| value.checked_div(applicable))
            .and_then(|value| u8::try_from(value).ok());
    }
    categories.into_values().collect()
}

fn coverage(plan: &CheckPlan, quality: &Quality) -> Vec<CoverageEntry> {
    plan.entries
        .iter()
        .map(|entry| {
            let reason = if !quality.clean() && entry.coverage == CoverageStatus::Tested {
                format!(
                    "capture quality is incomplete; passive check was evaluated cautiously ({})",
                    entry.reason
                )
            } else {
                entry.reason.clone()
            };
            CoverageEntry {
                check_id: entry.check_id.clone(),
                status: entry.coverage,
                reason,
            }
        })
        .collect()
}
