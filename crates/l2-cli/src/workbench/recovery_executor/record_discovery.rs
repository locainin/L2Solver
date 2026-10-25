//! Bounded record-schema hypotheses over already materialized frame evidence

mod input;
mod report;
mod work;

#[cfg(test)]
pub(in crate::workbench::recovery_executor) use input::collect_plan;
pub(in crate::workbench::recovery_executor) use input::{
    RecordDiscoveryPlan, apply_input_limits, collect_input_plan,
};
pub(in crate::workbench::recovery_executor) use report::{
    RecordDiscoveryContext, RecordSchemaReportLinks,
};

pub(super) const fn scan_work(plan: &RecordDiscoveryPlan) -> usize {
    plan.graph_work
}

#[cfg(test)]
pub(super) fn plan_has_inputs(plan: &RecordDiscoveryPlan) -> bool {
    plan.cohorts.values().any(|inputs| !inputs.is_empty())
}

pub(super) fn input_omissions(plan: &RecordDiscoveryPlan) -> Vec<super::RecoveryOmission> {
    plan.omissions
        .iter()
        .filter(|(_, omission)| omission.total > 0)
        .map(
            |(source_id, omission)| super::RecoveryOmission::RecordDiscoveryInputs {
                source_id: source_id.clone(),
                omitted_frames: omission.total,
                reason_counts: omission.reason_counts.clone(),
                examples: omission.examples.clone(),
            },
        )
        .collect()
}
pub(in crate::workbench::recovery_executor) use work::{
    case_max_cohort_input_bytes, case_work_bound, potential_framing_cohort_work_bound,
};
