//! Apply one retained derivation and report whether its constraints completed

use l2_workbench::{
    derivation::Recipe,
    journal::{DerivationInput, Journal},
};
use std::{error::Error, io::Write, path::Path};

pub(super) fn run(
    journal: &mut Journal,
    node: Option<u64>,
    hypothesis: Option<&str>,
    recipe_path: &Path,
    budget: usize,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let recipe: Recipe = super::read_json(recipe_path, budget)?;
    let selected = node
        .map(DerivationInput::BaseNode)
        .or_else(|| hypothesis.map(DerivationInput::DerivedOutput))
        .ok_or("missing derivation input")?;
    let id = journal.derive(selected, &recipe)?;
    let entry = journal.entry(&id)?;
    let complete = entry
        .derivation
        .as_ref()
        .is_some_and(|result| result.operation_completed && result.constraints_satisfied);
    serde_json::to_writer(output, &entry)?;
    Ok(complete)
}
