use super::{Family, SearchError, SearchLimits, SearchPlan};
use crate::derivation::{self, ConstraintStatus, DerivationLimits, DerivationReport, Recipe};
use crate::serialization::CountWriter;

pub(super) fn plan(
    input: &[u8],
    plan: &SearchPlan,
    limits: SearchLimits,
) -> Result<DerivationReport, SearchError> {
    if plan.families.is_empty()
        || plan.families.len() > 8
        || plan.constraints.is_empty()
        || plan.constraints.len() > 16
        || plan.max_depth == 0
        || plan.max_candidates == 0
        || limits.max_input_bytes == 0
        || limits.max_output_bytes == 0
        || limits.max_intermediate_bytes == 0
        || limits.max_work_bytes == 0
        || limits.max_key_tests == 0
        || limits.max_recipe_parameter_bytes == 0
    {
        return Err(SearchError::Invalid(
            "search plan and runtime budgets must be positive and within encoded plan bounds",
        ));
    }
    // Stop serialization at the plan budget before cloning variable parameters
    serde_json::to_writer(&mut CountWriter::new(8192), plan)
        .map_err(|_| SearchError::Invalid("search plan exceeds its encoded byte budget"))?;
    for (index, family) in plan.families.iter().enumerate() {
        if plan
            .families
            .get(..index)
            .is_some_and(|previous| previous.contains(family))
        {
            return Err(SearchError::Invalid("search families must be distinct"));
        }
        if let Family::KnownPlaintextXor {
            offset,
            bytes,
            key_lengths,
        } = family
        {
            validate_plaintext(*offset, bytes, key_lengths, limits.max_input_bytes)?;
        }
    }
    // Invalid checks cannot make an otherwise arbitrary output look successful
    let derivation_limits = DerivationLimits {
        max_input_bytes: limits.max_input_bytes,
        max_output_bytes: limits.max_output_bytes,
        max_intermediate_bytes: limits.max_intermediate_bytes,
        max_work_bytes: limits.max_work_bytes,
        max_steps: plan.max_depth,
        max_constraints: plan.constraints.len(),
        max_recipe_parameter_bytes: limits.max_recipe_parameter_bytes,
    };
    let checks = derivation::run_with_limits(
        input,
        &Recipe {
            steps: Vec::new(),
            constraints: plan.constraints.clone(),
        },
        derivation_limits,
    )?;
    if checks
        .constraints
        .iter()
        .any(|check| matches!(check.status, ConstraintStatus::Invalid { .. }))
    {
        return Err(SearchError::Invalid(
            "search constraints contain an invalid expectation",
        ));
    }
    // Reuse the validated baseline rather than hashing and checking the same input again
    Ok(checks)
}

fn validate_plaintext(
    offset: usize,
    bytes: &[u8],
    lengths: &[u16],
    max_input_bytes: usize,
) -> Result<(), SearchError> {
    if bytes.is_empty()
        || bytes.len() > 4096
        || offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > max_input_bytes)
        || lengths.is_empty()
        || lengths.len() > 16
        || lengths.iter().enumerate().any(|(index, length)| {
            !(1..=256).contains(length)
                || bytes.len() < usize::from(*length) * 2
                || lengths
                    .get(..index)
                    .is_some_and(|previous| previous.contains(length))
        })
    {
        return Err(SearchError::Invalid(
            "known plaintext needs distinct bounded key lengths and at least two periods per length",
        ));
    }
    Ok(())
}
