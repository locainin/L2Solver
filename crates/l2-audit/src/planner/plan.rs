//! Deterministic plan construction from catalog requirements

use super::catalog::CATALOG;
use super::coverage::PolicyCoverage;
use super::input::PlannerInput;
use super::requirements::{
    reason_for, resource_available, resource_requirement_label, scope_available,
};
use super::types::{CheckPlan, PlanEntry, Recommendation, RiskClass};
use crate::assessment::CoverageStatus;
use crate::{AuditError, Policy, SourceLabelMap};

/// Return the immutable, ordered check catalog
#[must_use]
pub const fn catalog() -> &'static [super::types::CheckDescriptor] {
    CATALOG
}

/// Build an applicability plan without transmitting any frame
#[must_use]
pub fn plan_passive(input: &PlannerInput, policy: &Policy) -> CheckPlan {
    plan_passive_with_coverage(input, PolicyCoverage::for_input(input, policy))
}

/// Build an applicability plan after resolving policy sources by stable labels
///
/// # Errors
/// Returns a source-mapping error when a schema-three policy cannot be resolved
/// for the supplied capture interfaces
pub fn plan_passive_with_source_labels(
    input: &PlannerInput,
    policy: &Policy,
    labels: &SourceLabelMap,
) -> Result<CheckPlan, AuditError> {
    let sources: Vec<_> = input.sources().iter().copied().collect();
    policy.validate_source_mapping(labels, &sources)?;
    let coverage = PolicyCoverage::for_input_with_source_labels(input, policy, labels)?;
    Ok(plan_passive_with_coverage(input, coverage))
}

fn plan_passive_with_coverage(input: &PlannerInput, policy_coverage: PolicyCoverage) -> CheckPlan {
    let mut entries = Vec::with_capacity(CATALOG.len());
    let mut recommendations = Vec::new();

    // The input constructors enforce this bound; retaining the guard keeps the
    // invariant explicit if more constructors are added later
    debug_assert!(input.agent_count() <= super::MAX_AGENT_COUNT);

    for descriptor in CATALOG {
        let missing_scope: Vec<_> = descriptor
            .prerequisites
            .iter()
            .filter(|requirement| !scope_available(**requirement, input, policy_coverage))
            .map(ToString::to_string)
            .collect();
        let missing_resources: Vec<_> = descriptor
            .prerequisites
            .iter()
            .filter(|requirement| {
                scope_available(**requirement, input, policy_coverage)
                    && !resource_available(**requirement, input, policy_coverage)
            })
            .map(|requirement| resource_requirement_label(*requirement, policy_coverage))
            .collect();
        let applicable = missing_scope.is_empty();
        // Scope failures make a check inapplicable. Resource failures keep the
        // check applicable while explaining why the active step was not run
        let missing = if applicable {
            missing_resources
        } else {
            missing_scope
        };
        let coverage = if !applicable {
            CoverageStatus::NotApplicable
        } else if descriptor.risk == RiskClass::Passive && missing.is_empty() {
            CoverageStatus::Tested
        } else {
            CoverageStatus::NotTested
        };
        let recommendation =
            applicable && matches!(descriptor.risk, RiskClass::SafeActive | RiskClass::Stateful);
        let reason = reason_for(applicable, coverage, &missing);
        if recommendation {
            recommendations.push(Recommendation {
                check_id: descriptor.id.to_owned(),
                title: descriptor.title.to_owned(),
                risk: descriptor.risk,
                reason: reason.clone(),
                required_agents: descriptor.required_agents,
            });
        }
        entries.push(PlanEntry {
            check_id: descriptor.id.to_owned(),
            title: descriptor.title.to_owned(),
            category: descriptor.category,
            risk: descriptor.risk,
            required_agents: descriptor.required_agents,
            packet_budget: descriptor.packet_budget,
            byte_budget: descriptor.byte_budget,
            duration_budget: descriptor.duration_budget,
            cleanup: descriptor.cleanup,
            applicable,
            coverage,
            reason,
            missing_requirements: missing,
            recommendation,
        });
    }

    // Keep the output bounded after adding the catalog entries
    recommendations.truncate(super::MAX_RECOMMENDATIONS);
    debug_assert!(entries.len() <= super::MAX_PLAN_ENTRIES);
    CheckPlan {
        entries,
        recommendations,
    }
}
