use super::{
    DerivationLimits, DerivationReport, DerivationStatus, OperandLocation, Operation, Recipe,
    StepFailure, StepReport, StepStatus,
    memory::{Admission, AdmissionError, Buffer, BufferError, Shared, Unrestricted},
    transform::TransformError,
};
use crate::evidence::Case;
use crate::job::{MemoryError, MemoryLease};
use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerivationError {
    InputTooLong {
        length: usize,
        limit: usize,
    },
    TooManySteps {
        count: usize,
        limit: usize,
    },
    TooManyConstraints {
        count: usize,
        limit: usize,
    },
    RecipeParametersTooLarge {
        limit: usize,
    },
    InvalidLimits,
    AllocationFailed,
    EvidenceCaseRequired {
        location: OperandLocation,
    },
    SelectedInputRequired {
        location: OperandLocation,
    },
    SelectedInputNodeMissing {
        node_id: u64,
    },
    SelectedInputBlobMissing {
        node_id: u64,
    },
    OperandNodeMissing {
        location: OperandLocation,
        node_id: u64,
    },
    OperandBlobMissing {
        location: OperandLocation,
        node_id: u64,
    },
    OperandRangeOverflow {
        location: OperandLocation,
        offset: u64,
        length: u64,
    },
    OperandRangeOutOfBounds {
        location: OperandLocation,
        offset: u64,
        length: u64,
        blob_length: usize,
    },
}

impl fmt::Display for DerivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { length, limit } => {
                write!(formatter, "input length {length} exceeds {limit} bytes")
            }
            Self::TooManySteps { count, limit } => {
                write!(formatter, "recipe has {count} steps; maximum is {limit}")
            }
            Self::TooManyConstraints { count, limit } => {
                write!(
                    formatter,
                    "recipe has {count} constraints; maximum is {limit}"
                )
            }
            Self::RecipeParametersTooLarge { limit } => {
                write!(formatter, "recipe parameters exceed {limit} bytes")
            }
            Self::InvalidLimits => formatter.write_str("derivation budgets must be positive"),
            Self::AllocationFailed => {
                formatter.write_str("derivation could not allocate the configured result")
            }
            Self::EvidenceCaseRequired { location } => write!(
                formatter,
                "derivation {} contains a node-range operand and requires an evidence case",
                format_operand_location(*location),
            ),
            Self::SelectedInputRequired { location } => write!(
                formatter,
                "derivation {} contains a selected-input-relative operand and requires a selected input node and evidence case",
                format_operand_location(*location),
            ),
            Self::SelectedInputNodeMissing { node_id } => {
                write!(formatter, "selected input node {node_id} is missing")
            }
            Self::SelectedInputBlobMissing { node_id } => write!(
                formatter,
                "selected input node {node_id} has no retained blob"
            ),
            Self::OperandNodeMissing { location, node_id } => write!(
                formatter,
                "derivation {} references missing operand node {node_id}",
                format_operand_location(*location),
            ),
            Self::OperandBlobMissing { location, node_id } => write!(
                formatter,
                "derivation {} operand node {node_id} has no retained blob",
                format_operand_location(*location),
            ),
            Self::OperandRangeOverflow {
                location,
                offset,
                length,
            } => write!(
                formatter,
                "derivation {} operand range {offset}+{length} overflows",
                format_operand_location(*location),
            ),
            Self::OperandRangeOutOfBounds {
                location,
                offset,
                length,
                blob_length,
            } => write!(
                formatter,
                "derivation {} operand range {offset}+{length} exceeds retained blob length {blob_length}",
                format_operand_location(*location),
            ),
        }
    }
}

impl Error for DerivationError {}

#[derive(Debug)]
pub enum AdmittedDerivationError {
    Derivation(DerivationError),
    Memory(MemoryError),
    UnsupportedOperation,
}

impl fmt::Display for AdmittedDerivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Derivation(error) => write!(formatter, "derivation failed: {error}"),
            Self::Memory(error) => write!(formatter, "derivation admission failed: {error}"),
            Self::UnsupportedOperation => formatter.write_str("unsupported admitted recipe"),
        }
    }
}

impl Error for AdmittedDerivationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Derivation(error) => Some(error),
            Self::Memory(error) => Some(error),
            Self::UnsupportedOperation => None,
        }
    }
}

enum EngineError<E> {
    Derivation(DerivationError),
    Admission(E),
}

fn format_operand_location(location: OperandLocation) -> String {
    match location {
        OperandLocation::Step { step_index } => format!("step {step_index}"),
        OperandLocation::Constraint { constraint_index } => {
            format!("constraint {constraint_index}")
        }
    }
}

/// Apply only the operations and checks listed in a bounded recipe
///
/// Step failures remain in the report, and later steps are marked as skipped
///
/// # Errors
/// Rejects input, step, constraint, or aggregate recipe parameter limits
pub fn run(input: &[u8], recipe: &Recipe) -> Result<DerivationReport, DerivationError> {
    run_with_limits(input, recipe, DerivationLimits::default())
}

/// Apply a recipe under explicit checked input, output, work, and parameter budgets
///
/// # Errors
/// Rejects invalid budgets or recipe sizes that cannot be represented within them
pub fn run_with_limits(
    input: &[u8],
    recipe: &Recipe,
    limits: DerivationLimits,
) -> Result<DerivationReport, DerivationError> {
    validate_plain_request(input, recipe, limits)?;
    run_unadmitted(input, recipe, limits)
}

/// Apply supported decoder recipes while the caller retains the output charge
///
/// The lease must outlive the returned report, including reports with a failed step
/// Errors leave the original lease unchanged after temporary buffers are dropped
/// Charges cover logical buffer capacities and bounded workspace, not allocator overhead or RSS
///
/// # Errors
/// Returns an error for invalid requests, unsupported recipes, or denied memory admission
pub fn run_with_memory(
    input: &[u8],
    recipe: &Recipe,
    limits: DerivationLimits,
    memory: &mut MemoryLease,
) -> Result<DerivationReport, AdmittedDerivationError> {
    validate_plain_request(input, recipe, limits).map_err(AdmittedDerivationError::Derivation)?;
    if !supports_admission(recipe) {
        return Err(AdmittedDerivationError::UnsupportedOperation);
    }
    match run_validated(input, recipe, limits, Shared(memory)) {
        Ok(report) => Ok(report),
        Err(EngineError::Derivation(error)) => Err(AdmittedDerivationError::Derivation(error)),
        Err(EngineError::Admission(AdmissionError::Memory(error))) => {
            Err(AdmittedDerivationError::Memory(error))
        }
        Err(EngineError::Admission(AdmissionError::UnsupportedOperation)) => {
            Err(AdmittedDerivationError::UnsupportedOperation)
        }
    }
}

const fn supports_admission(recipe: &Recipe) -> bool {
    if !recipe.constraints.is_empty() {
        return false;
    }
    let ([decoder] | [Operation::Slice { .. }, decoder]) = recipe.steps.as_slice() else {
        return false;
    };
    matches!(
        decoder,
        Operation::HexDecode {}
            | Operation::Base64Decode { .. }
            | Operation::GzipDecompress {}
            | Operation::ZlibDecompress {}
            | Operation::XorRepeat { .. }
    )
}

fn validate_plain_request(
    input: &[u8],
    recipe: &Recipe,
    limits: DerivationLimits,
) -> Result<(), DerivationError> {
    if let Some(location) = super::operands::first_selected_input_reference(recipe) {
        return Err(DerivationError::SelectedInputRequired { location });
    }
    if let Some(location) = super::operands::first_external_reference(recipe) {
        return Err(DerivationError::EvidenceCaseRequired { location });
    }
    validate_request(input, recipe, limits)
}

fn validate_request(
    input: &[u8],
    recipe: &Recipe,
    limits: DerivationLimits,
) -> Result<(), DerivationError> {
    if limits.max_input_bytes == 0
        || limits.max_output_bytes == 0
        || limits.max_intermediate_bytes == 0
        || limits.max_work_bytes == 0
        || limits.max_steps == 0
        || limits.max_constraints == 0
        || limits.max_recipe_parameter_bytes == 0
    {
        return Err(DerivationError::InvalidLimits);
    }
    if input.len() > limits.max_input_bytes {
        return Err(DerivationError::InputTooLong {
            length: input.len(),
            limit: limits.max_input_bytes,
        });
    }
    validate_recipe_identity_with_limits(recipe, limits)
}

pub(super) fn validate_recipe_identity(recipe: &Recipe) -> Result<(), DerivationError> {
    validate_recipe_identity_with_limits(recipe, DerivationLimits::default())
}

fn validate_recipe_identity_with_limits(
    recipe: &Recipe,
    limits: DerivationLimits,
) -> Result<(), DerivationError> {
    if recipe.steps.len() > limits.max_steps {
        return Err(DerivationError::TooManySteps {
            count: recipe.steps.len(),
            limit: limits.max_steps,
        });
    }
    if recipe.constraints.len() > limits.max_constraints {
        return Err(DerivationError::TooManyConstraints {
            count: recipe.constraints.len(),
            limit: limits.max_constraints,
        });
    }
    validate_recipe_parameter_size(&recipe.steps, &recipe.constraints, limits)?;
    Ok(())
}

fn run_unadmitted(
    input: &[u8],
    recipe: &Recipe,
    limits: DerivationLimits,
) -> Result<DerivationReport, DerivationError> {
    match run_validated(input, recipe, limits, Unrestricted) {
        Ok(report) => Ok(report),
        Err(EngineError::Derivation(error)) => Err(error),
        Err(EngineError::Admission(never)) => match never {},
    }
}

fn run_validated<A: Admission>(
    input: &[u8],
    recipe: &Recipe,
    limits: DerivationLimits,
    admission: A,
) -> Result<DerivationReport, EngineError<A::Error>> {
    // The copied input stays charged before any hashing or report allocation
    let mut current =
        Buffer::with_capacity(input.len(), &admission).map_err(|error| match error {
            BufferError::Allocation => EngineError::Derivation(DerivationError::AllocationFailed),
            BufferError::Admission(error) => EngineError::Admission(error),
        })?;
    current.bytes.extend_from_slice(input);
    let metadata_bytes = if admission.is_active() {
        metadata_bound(recipe).map_err(EngineError::Derivation)?
    } else {
        0
    };
    let mut metadata = admission
        .reserve(metadata_bytes)
        .map_err(EngineError::Admission)?;
    let input_sha256 = crate::sha256(input);
    let execution = execute_steps(current, recipe, limits, input_sha256.clone(), &admission)?;

    let constraints = super::constraints::evaluate(
        &recipe.constraints,
        &execution.output.bytes,
        &execution.output_sha256,
        execution.failed_step,
        limits.max_output_bytes,
    );
    let (output, lease) = execution.output.into_parts();
    let report = DerivationReport {
        status: execution
            .failed_step
            .map_or(DerivationStatus::Completed, |step_index| {
                DerivationStatus::Failed { step_index }
            }),
        input_length: input.len(),
        input_sha256,
        output,
        output_sha256: execution.output_sha256,
        steps: execution.steps,
        constraints,
        intermediate_bytes: execution.intermediate_bytes,
        work_bytes: execution.work_bytes,
    };
    if admission.is_active() {
        let retained = report_metadata_bytes(&report).map_err(EngineError::Derivation)?;
        if retained > metadata_bytes {
            // Reconcile actual capacities while the report still owns its allocations
            admission
                .resize(&mut metadata, retained)
                .map_err(EngineError::Admission)?;
        }
    }
    // Transfer both charges only after the report owns their allocations
    admission.finish(lease, metadata);
    Ok(report)
}

fn metadata_bound(recipe: &Recipe) -> Result<u64, DerivationError> {
    // A digest has 64 hex bytes, with extra room for string formatting growth
    const DIGEST_ALLOCATION_BYTES: usize = 256;
    let steps = recipe.steps.len();
    // Two hashes remain per step, with three more live during replacement
    let digest_bytes = steps
        .checked_mul(2)
        .and_then(|count| count.checked_add(3))
        .and_then(|count| count.checked_mul(DIGEST_ALLOCATION_BYTES));
    // Reserve extra room for Vec capacity beyond the requested report count
    let report_bytes = steps
        .checked_mul(std::mem::size_of::<StepReport>())
        .and_then(|bytes| bytes.checked_mul(2));
    // Each step report clones its operation, including any XOR key bytes
    let key_bytes = recipe.steps.iter().try_fold(0_usize, |total, operation| {
        let length = match operation {
            Operation::XorRepeat { key, .. } => key.len(),
            _ => 0,
        };
        total.checked_add(length)
    });
    digest_bytes
        .and_then(|digest| report_bytes.and_then(|reports| digest.checked_add(reports)))
        .and_then(|total| key_bytes.and_then(|keys| total.checked_add(keys)))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(DerivationError::AllocationFailed)
}

fn report_metadata_bytes(report: &DerivationReport) -> Result<u64, DerivationError> {
    let mut bytes = report
        .steps
        .capacity()
        .checked_mul(std::mem::size_of::<StepReport>())
        .and_then(|bytes| bytes.checked_add(report.input_sha256.capacity()))
        .and_then(|bytes| bytes.checked_add(report.output_sha256.capacity()))
        .ok_or(DerivationError::AllocationFailed)?;
    for step in &report.steps {
        bytes = bytes
            .checked_add(step.input_sha256.as_ref().map_or(0, String::capacity))
            .and_then(|bytes| {
                bytes.checked_add(step.output_sha256.as_ref().map_or(0, String::capacity))
            })
            .and_then(|bytes| match &step.operation {
                Operation::XorRepeat { key, .. } => bytes.checked_add(key.capacity()),
                _ => Some(bytes),
            })
            .ok_or(DerivationError::AllocationFailed)?;
    }
    u64::try_from(bytes).map_err(|_| DerivationError::AllocationFailed)
}

/// Apply a recipe after resolving retained node ranges from one evidence case
///
/// The returned reports keep each original reference and include the provider range hash
///
/// # Errors
/// Rejects invalid budgets, missing provider nodes or blobs, invalid byte ranges,
/// or recipe sizes that exceed the configured limits
pub fn run_with_case(
    input: &[u8],
    recipe: &Recipe,
    case: &Case,
    limits: DerivationLimits,
) -> Result<DerivationReport, DerivationError> {
    if super::operands::first_external_reference(recipe).is_none() {
        return run_with_limits(input, recipe, limits);
    }
    // Bound declared operand lengths before cloning the recipe or copying retained ranges
    validate_request(input, recipe, limits)?;
    let resolved = super::operands::resolve(recipe, case, None)?;
    Ok(retain_operand_provenance(
        run_unadmitted(input, &resolved.recipe, limits)?,
        recipe,
        resolved,
    ))
}

/// Apply a recipe to a selected retained node, resolving ranges relative to that node
///
/// This entry point binds selected-input ranges to the node's current retained blob
///
/// # Errors
/// Rejects missing input nodes or blobs, invalid budgets, unresolved operand nodes,
/// or recipe sizes that exceed the configured limits
pub fn run_with_selected_input(
    input_node_id: u64,
    recipe: &Recipe,
    case: &Case,
    limits: DerivationLimits,
) -> Result<DerivationReport, DerivationError> {
    let node = case
        .nodes()
        .iter()
        .find(|node| node.id == input_node_id)
        .ok_or(DerivationError::SelectedInputNodeMissing {
            node_id: input_node_id,
        })?;
    let blob_id = node
        .blob
        .as_deref()
        .ok_or(DerivationError::SelectedInputBlobMissing {
            node_id: input_node_id,
        })?;
    let input = case
        .blobs()
        .iter()
        .find(|blob| blob.id == blob_id)
        .map(|blob| blob.bytes.as_slice())
        .ok_or(DerivationError::SelectedInputBlobMissing {
            node_id: input_node_id,
        })?;
    if super::operands::first_external_reference(recipe).is_none() {
        return run_with_limits(input, recipe, limits);
    }
    // Validate declared lengths before copying selected or external operand ranges
    validate_request(input, recipe, limits)?;
    let resolved = super::operands::resolve(recipe, case, Some(input_node_id))?;
    Ok(retain_operand_provenance(
        run_unadmitted(input, &resolved.recipe, limits)?,
        recipe,
        resolved,
    ))
}

fn retain_operand_provenance(
    mut report: DerivationReport,
    recipe: &Recipe,
    resolved: super::operands::ResolvedOperands,
) -> DerivationReport {
    for ((step, original_operation), operand_provenance) in report
        .steps
        .iter_mut()
        .zip(&recipe.steps)
        .zip(resolved.step_provenance)
    {
        step.operation = original_operation.clone();
        step.operand_provenance = operand_provenance;
    }
    for ((constraint, original_constraint), operand_provenance) in report
        .constraints
        .iter_mut()
        .zip(&recipe.constraints)
        .zip(resolved.constraint_provenance)
    {
        constraint.constraint = original_constraint.clone();
        constraint.operand_provenance = operand_provenance;
    }
    report
}

struct ExecutionResult<A: Admission> {
    output: Buffer<A>,
    output_sha256: String,
    steps: Vec<StepReport>,
    intermediate_bytes: usize,
    work_bytes: usize,
    failed_step: Option<usize>,
}

struct StepExecution<A: Admission> {
    output: Option<(Buffer<A>, String)>,
    report: StepReport,
    intermediate_bytes: usize,
    work_bytes: usize,
    failed: bool,
}

#[derive(Clone, Copy)]
struct StepBudget {
    remaining_intermediate: usize,
    remaining_work: usize,
    reserved_work: usize,
}

fn execute_steps<A: Admission>(
    mut current: Buffer<A>,
    recipe: &Recipe,
    limits: DerivationLimits,
    input_sha256: String,
    admission: &A,
) -> Result<ExecutionResult<A>, EngineError<A::Error>> {
    let mut current_sha256 = input_sha256;
    let mut intermediate_bytes = 0_usize;
    let mut work_bytes = 0_usize;
    let mut failed_step = None;
    let mut steps = Vec::new();
    steps
        .try_reserve_exact(recipe.steps.len())
        .map_err(|_| EngineError::Derivation(DerivationError::AllocationFailed))?;

    for (step_index, operation) in recipe.steps.iter().enumerate() {
        if let Some(after_step) = failed_step {
            steps.push(skipped_step(operation, after_step));
            continue;
        }
        let execution = execute_step(
            &current.bytes,
            &current_sha256,
            operation,
            limits,
            intermediate_bytes,
            work_bytes,
            admission,
        )?;
        if execution.failed {
            failed_step = Some(step_index);
        }
        if let Some((output, output_sha256)) = execution.output {
            current_sha256 = output_sha256;
            current = output;
        }
        intermediate_bytes += execution.intermediate_bytes;
        work_bytes += execution.work_bytes;
        steps.push(execution.report);
    }

    Ok(ExecutionResult {
        output: current,
        output_sha256: current_sha256,
        steps,
        intermediate_bytes,
        work_bytes,
        failed_step,
    })
}

fn execute_step<A: Admission>(
    input: &[u8],
    input_sha256: &str,
    operation: &Operation,
    limits: DerivationLimits,
    intermediate_bytes: usize,
    work_bytes: usize,
    admission: &A,
) -> Result<StepExecution<A>, EngineError<A::Error>> {
    let input_length = input.len();
    let remaining_intermediate = limits.max_intermediate_bytes - intermediate_bytes;
    let remaining_work = limits.max_work_bytes - work_bytes;
    let reserved_work = match reserve_operation_work(input_length, operation, remaining_work) {
        Ok(reserved_work) => reserved_work,
        Err(charged_work) => {
            return Ok(failed_step_execution(
                operation,
                input_length,
                input_sha256,
                StepFailure::WorkBudgetExceeded {
                    limit: limits.max_work_bytes,
                },
                charged_work,
            ));
        }
    };
    execute_reserved_step(
        input,
        input_sha256,
        operation,
        limits,
        StepBudget {
            remaining_intermediate,
            remaining_work,
            reserved_work,
        },
        admission,
    )
}

fn reserve_operation_work(
    input_length: usize,
    operation: &Operation,
    remaining_work: usize,
) -> Result<usize, usize> {
    if input_length > remaining_work {
        return Err(0);
    }
    let Some(operation_overhead) = super::transform::crypto_work_overhead(input_length, operation)
    else {
        return Err(input_length);
    };
    let Some(reserved_work) = input_length.checked_add(operation_overhead) else {
        return Err(input_length);
    };
    if reserved_work > remaining_work {
        return Err(input_length);
    }
    Ok(reserved_work)
}

fn execute_reserved_step<A: Admission>(
    input: &[u8],
    input_sha256: &str,
    operation: &Operation,
    limits: DerivationLimits,
    step_budget: StepBudget,
    admission: &A,
) -> Result<StepExecution<A>, EngineError<A::Error>> {
    let input_length = input.len();
    let work_output_limit = step_budget.remaining_work - step_budget.reserved_work;
    let ordinary_output_limit = limits
        .max_output_bytes
        .min(step_budget.remaining_intermediate);
    let work_limited_output = work_output_limit < ordinary_output_limit;
    let output_limit = ordinary_output_limit.min(work_output_limit);
    // Reserve input scanning before applying a decoder, then cap output by remaining work
    let budget = super::transform::OutputBudget {
        remaining_intermediate: step_budget.remaining_intermediate,
        max_output: output_limit,
        max_intermediate: limits.max_intermediate_bytes,
        max_key_bytes: limits.max_input_bytes,
    };
    match super::transform::apply(input, operation, budget, admission) {
        Ok(output) => {
            let output_length = output.bytes.len();
            let output_sha256 = crate::sha256(&output.bytes);
            Ok(StepExecution {
                report: StepReport {
                    operation: operation.clone(),
                    operand_provenance: Vec::new(),
                    input_length: Some(input_length),
                    input_sha256: Some(input_sha256.to_owned()),
                    output_length: Some(output_length),
                    output_sha256: Some(output_sha256.clone()),
                    status: StepStatus::Applied,
                },
                output: Some((output, output_sha256)),
                intermediate_bytes: output_length,
                work_bytes: step_budget.reserved_work + output_length,
                failed: false,
            })
        }
        Err(TransformError::Step(StepFailure::OutputLimitExceeded { .. }))
            if work_limited_output =>
        {
            Ok(failed_step_execution(
                operation,
                input_length,
                input_sha256,
                StepFailure::WorkBudgetExceeded {
                    limit: limits.max_work_bytes,
                },
                input_length,
            ))
        }
        Err(TransformError::Step(error)) => Ok(failed_step_execution(
            operation,
            input_length,
            input_sha256,
            error,
            step_budget.reserved_work,
        )),
        Err(TransformError::Admission(error)) => Err(EngineError::Admission(error)),
    }
}

fn failed_step_execution<A: Admission>(
    operation: &Operation,
    input_length: usize,
    input_sha256: &str,
    error: StepFailure,
    work_bytes: usize,
) -> StepExecution<A> {
    StepExecution {
        output: None,
        report: failed_step_report(operation, input_length, input_sha256.to_owned(), error),
        intermediate_bytes: 0,
        work_bytes,
        failed: true,
    }
}

pub(super) fn validate_constraint_parameter_size(
    constraints: &[super::Constraint],
) -> Result<(), DerivationError> {
    validate_recipe_parameter_size(&[], constraints, DerivationLimits::default())
}

fn validate_recipe_parameter_size(
    steps: &[Operation],
    constraints: &[super::Constraint],
    limits: DerivationLimits,
) -> Result<(), DerivationError> {
    let mut parameter_bytes = 0_usize;
    // Bound the data cloned into step and constraint reports before allocating them
    for operation in steps {
        let operation_bytes = match operation {
            Operation::XorRepeat { key, .. } => key.len(),
            Operation::Sha256CounterXor { seed, .. } => {
                operand_parameter_length(seed, limits.max_recipe_parameter_bytes)?
            }
            Operation::AesGcmDecrypt {
                key,
                nonce,
                associated_data,
                ..
            } => checked_operand_sum(
                [key, nonce, associated_data],
                limits.max_recipe_parameter_bytes,
            )?,
            Operation::ScryptDerive { salt, .. } => {
                operand_parameter_length(salt, limits.max_recipe_parameter_bytes)?
            }
            Operation::Select { indices }
            | Operation::SelectBits { indices, .. }
            | Operation::Permute { indices } => indices
                .len()
                .checked_mul(std::mem::size_of::<usize>())
                .ok_or(DerivationError::RecipeParametersTooLarge {
                    limit: limits.max_recipe_parameter_bytes,
                })?,
            _ => 0,
        };
        parameter_bytes = checked_parameter_total(
            parameter_bytes,
            operation_bytes,
            limits.max_recipe_parameter_bytes,
        )?;
    }
    for constraint in constraints {
        let constraint_bytes = match constraint {
            super::Constraint::Prefix { bytes } => bytes.len(),
            super::Constraint::Sha256 { expected_hex } => expected_hex.len(),
            super::Constraint::AesGcm {
                key,
                nonce,
                associated_data,
            } => checked_operand_sum(
                [key, nonce, associated_data],
                limits.max_recipe_parameter_bytes,
            )?,
            _ => 0,
        };
        parameter_bytes = checked_parameter_total(
            parameter_bytes,
            constraint_bytes,
            limits.max_recipe_parameter_bytes,
        )?;
    }
    Ok(())
}

fn operand_parameter_length(
    operand: &super::OperandRef,
    limit: usize,
) -> Result<usize, DerivationError> {
    match operand {
        super::OperandRef::Literal(bytes) => Ok(bytes.as_bytes().len()),
        super::OperandRef::NodeRange { length, .. } => usize::try_from(*length)
            .map_err(|_| DerivationError::RecipeParametersTooLarge { limit }),
        super::OperandRef::SelectedInputRange { length, .. } => usize::try_from(*length)
            .map_err(|_| DerivationError::RecipeParametersTooLarge { limit }),
    }
}

fn checked_operand_sum(
    operands: [&super::OperandRef; 3],
    limit: usize,
) -> Result<usize, DerivationError> {
    operands.into_iter().try_fold(0_usize, |total, operand| {
        let length = operand_parameter_length(operand, limit)?;
        checked_parameter_total(total, length, limit)
    })
}

fn checked_parameter_total(
    total: usize,
    length: usize,
    limit: usize,
) -> Result<usize, DerivationError> {
    let total = total
        .checked_add(length)
        .ok_or(DerivationError::RecipeParametersTooLarge { limit })?;
    if total > limit {
        return Err(DerivationError::RecipeParametersTooLarge { limit });
    }
    Ok(total)
}

fn failed_step_report(
    operation: &Operation,
    input_length: usize,
    input_sha256: String,
    error: StepFailure,
) -> StepReport {
    StepReport {
        operation: operation.clone(),
        operand_provenance: Vec::new(),
        input_length: Some(input_length),
        input_sha256: Some(input_sha256),
        output_length: None,
        output_sha256: None,
        status: StepStatus::Failed { error },
    }
}

fn skipped_step(operation: &Operation, after_step: usize) -> StepReport {
    StepReport {
        operation: operation.clone(),
        operand_provenance: Vec::new(),
        input_length: None,
        input_sha256: None,
        output_length: None,
        output_sha256: None,
        status: StepStatus::Skipped { after_step },
    }
}
