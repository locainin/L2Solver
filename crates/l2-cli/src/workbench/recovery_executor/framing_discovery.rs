//! Case-wide automatic framing discovery over compatible retained TCP runs

mod input;
mod report;
mod work;

pub(in crate::workbench::recovery_executor) use input::{FramingDiscoveryPlan, collect_plan};
pub(in crate::workbench::recovery_executor) use report::FramingDiscoveryContext;
#[cfg(test)]
pub(in crate::workbench::recovery_executor) use report::bounded_report_bytes;
pub(in crate::workbench::recovery_executor) use work::{
    case_max_cohort_input_bytes, case_work_bound, post_framing_record_phase_work_bound,
};

pub(super) const fn scan_work(plan: &FramingDiscoveryPlan) -> usize {
    plan.graph_work
}

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_framing_plan_identity.rs"]
mod plan_identity_tests;
