//! Bounded record-schema hypotheses over already materialized frame evidence

mod analysis;
pub(in crate::workbench::recovery_executor) use report::checkpoint;
mod input;
mod report;
mod work;

#[cfg(test)]
pub(in crate::workbench::recovery_executor) use input::collect_plan;
pub(in crate::workbench::recovery_executor) use input::{
    RecordCohortKey, RecordCohortOrigin, RecordDiscoveryPlan, RecordFrameInput, apply_input_limits,
    collect_input_plan, collect_input_plan_excluding,
};
pub(in crate::workbench::recovery_executor) use report::{
    PendingRecordSuffix, RecordDiscoveryContext, RecordSchemaReportLinks,
};

pub(super) const fn scan_work(plan: &RecordDiscoveryPlan) -> usize {
    plan.graph_work
}

#[cfg(test)]
pub(super) fn plan_has_inputs(plan: &RecordDiscoveryPlan) -> bool {
    plan.cohorts.values().any(|inputs| !inputs.is_empty())
}

pub(super) fn input_omissions(plan: &RecordDiscoveryPlan) -> Vec<super::RecoveryOmission> {
    let mut result = Vec::new();
    for (source_id, omission) in &plan.omissions {
        let eligibility = omission.eligibility_only();
        if eligibility.total > 0 {
            result.push(super::RecoveryOmission::RecordDiscoveryInputs {
                source_id: source_id.clone(),
                omitted_frames: eligibility.total,
                reason_counts: eligibility.reason_counts,
                examples: eligibility.examples,
            });
        }
        let learning = omission.learning_only();
        if learning.total > 0 {
            result.push(super::RecoveryOmission::RecordDiscoveryLearningSample {
                source_id: source_id.clone(),
                unsampled_frames: learning.total,
                reason_counts: learning.reason_counts,
                examples: learning.examples,
            });
        }
    }
    result
}
pub(in crate::workbench::recovery_executor) use work::{
    case_max_cohort_input_bytes, case_work_bound, potential_framing_cohort_work_bound,
};
