use super::{input, load, read_bounded};
use crate::arguments::DecodeArgs;
use l2_workbench::derivation::Recipe;
use std::{error::Error, io::Write};

pub mod service;

pub(super) fn run(args: &DecodeArgs, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let mut case = load(&args.case)?;
    let recipe_bytes = read_bounded(input::regular(&args.recipe)?, args.max_recipe_bytes.get())?;
    let recipe: Recipe = serde_json::from_slice(&recipe_bytes)?;
    let outcome = service::apply_recipe(
        &mut case,
        &args.nodes,
        &recipe,
        args.limits(),
        service::DecodeBatchLimits {
            items: args.max_items.get(),
            total_input_bytes: args.max_total_input_bytes.get(),
            total_work_bytes: args.max_total_work_bytes.get(),
            total_output_bytes: args.max_total_output_bytes.get(),
            total_report_bytes: args.max_total_report_bytes.get(),
        },
    )?;
    case.write_json(output)?;
    Ok(outcome.is_complete())
}
