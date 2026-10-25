//! Run a bounded discovery plan over exact native evidence mappings

use super::{carrier_plan::parse_view, input, load, read_bounded};
use l2_workbench::carrier::discovery::{DiscoveryPlan, discover_case_with_view};
use serde::Serialize;
use std::{error::Error, io::Write, path::Path};

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CliDiscoveryReport<'a> {
    plan_document_bytes: usize,
    plan_document_budget_bytes: usize,
    #[serde(flatten)]
    report: &'a l2_workbench::carrier::discovery::DiscoveryReport,
}

/// Execute explicit bit-plane hypotheses and retain the full bounded report
pub(super) fn run(
    case_path: &Path,
    node_ids: &[u64],
    view_name: &str,
    plan_path: &Path,
    max_plan_bytes: usize,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let view = parse_view(view_name)?;
    if max_plan_bytes == 0 || max_plan_bytes.checked_add(1).is_none() {
        return Err("max-plan-bytes must be positive and allow oversize detection".into());
    }
    // The prior carrier command uses this default; callers may raise it for larger explicit plans
    let plan_bytes = read_bounded(input::regular_no_follow(plan_path)?, max_plan_bytes)?;
    let plan_document_bytes = plan_bytes.len();
    let plan: DiscoveryPlan = serde_json::from_slice(&plan_bytes)?;
    let case = load(case_path)?;
    let report = discover_case_with_view(&case, node_ids, view, &plan)?;
    serde_json::to_writer(
        output,
        &CliDiscoveryReport {
            plan_document_bytes,
            plan_document_budget_bytes: max_plan_bytes,
            report: &report,
        },
    )?;
    Ok(case.collection_complete() && report.enumeration_complete && report.printable_runs_complete)
}
