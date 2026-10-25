use super::{input, load, read_bounded, selected};
use l2_workbench::{
    experiment::{self, ExperimentMode, ExperimentStatus, MutationPlan},
    hypothesis::{self, SearchPlan},
};
use serde_json::json;
use std::{error::Error, io::Write, path::Path};

pub(super) fn search(
    path: &Path,
    id: u64,
    plan: &Path,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let case = load(path)?;
    let (node, bytes) = selected::bytes(&case, id)?;
    let plan: SearchPlan = serde_json::from_slice(&read_bounded(input::regular(plan)?, 8192)?)?;
    let report = hypothesis::search(bytes, &plan)?;
    let complete = case.collection_complete() && report.search_exhaustive_within_plan;
    serde_json::to_writer(
        output,
        &json!({"input": {"node_id":node.id,"kind":node.kind,"blob":node.blob,"source_ranges":node.ranges},
        "case_collection_complete":case.collection_complete(), "search":report}),
    )?;
    Ok(complete)
}

pub(super) fn experiment(
    path: &Path,
    id: u64,
    plan: &Path,
    mode: &str,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let case = load(path)?;
    let (node, bytes) = selected::bytes(&case, id)?;
    let plan: MutationPlan = serde_json::from_slice(&read_bounded(input::regular(plan)?, 65_536)?)?;
    let mode = match mode {
        "offline" => ExperimentMode::Offline,
        "loopback" => ExperimentMode::Loopback,
        _ => return Err("experiment mode must be offline or loopback".into()),
    };
    let report = experiment::run(bytes, &plan, mode)?;
    let complete = case.collection_complete() && report.status == ExperimentStatus::Complete;
    serde_json::to_writer(
        output,
        &json!({"input": {"node_id":node.id,"kind":node.kind,"blob":node.blob,"source_ranges":node.ranges},
        "case_collection_complete":case.collection_complete(), "experiment":report}),
    )?;
    Ok(complete)
}
