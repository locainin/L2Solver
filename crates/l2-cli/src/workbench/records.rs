//! Explicit repeated-record parsing with durable object and issue receipts

mod analysis;
mod evidence;
pub mod service;

#[cfg(test)]
#[path = "../../tests/workbench/records_service.rs"]
mod service_tests;

use super::{input, load, read_bounded};
use crate::arguments::RecordsArgs;
use std::{error::Error, io::Write};

pub(super) fn run(args: &RecordsArgs, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let mut case = load(&args.case)?;
    let schema_bytes = read_bounded(
        input::regular_no_follow(&args.schema)?,
        args.max_schema_bytes.get(),
    )?;
    let schema = serde_json::from_slice(&schema_bytes)?;
    service::apply(
        &mut case,
        &service::RecordServiceInput {
            selected_node_ids: &args.nodes,
            count_sources: (!args.count_sources.is_empty()).then_some(&args.count_sources),
            schema: &schema,
            limits: args.limits(),
        },
    )?;
    case.write_json(output)?;

    // Incomplete groups are findings with durable diagnostics, not execution failures
    Ok(case.collection_complete())
}
