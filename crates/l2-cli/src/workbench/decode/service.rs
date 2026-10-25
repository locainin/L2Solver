//! Reusable in-process service for explicit byte derivation stages

use super::super::{file_signatures, selected};
use l2_workbench::{
    derivation::{
        self, ConstraintReport, ConstraintStatus, DerivationLimits, DerivationReport,
        DerivationStatus, StepFailure, StepReport, StepStatus,
    },
    evidence::{Case, Edge, EvidenceStatus},
};
use serde::Serialize;
use std::{
    error::Error,
    io::{self, Write},
};

// Candidate results and earlier collection omissions describe separate facts
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Completeness of all selected derivations and constraints
pub enum DecodeStageCompleteness {
    /// Every selected derivation and its constraints completed
    Complete,
    /// At least one selected candidate failed or did not satisfy its constraints
    Incomplete {
        /// Candidates with a failed derivation
        failed_items: usize,
        /// Completed candidates with at least one unsatisfied constraint
        rejected_items: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Whether the input case already recorded collection omissions
pub enum DecodeOmissionState {
    /// The case collection is complete
    None,
    /// The case was already incomplete before this stage
    ExistingCollectionOmissions,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Result of processing one selected node
pub enum DecodeItemState {
    /// Derivation and every explicit constraint completed
    Completed,
    /// Derivation completed but at least one constraint was not satisfied
    Rejected,
    /// The derivation could not complete
    Failed,
}

// Created node ids let later stages link results without reading case JSON
#[derive(Clone, Debug, Eq, PartialEq)]
/// Nodes recorded for one selected input
pub struct DecodeCreatedNodes {
    /// Input node used for this derivation
    pub input_node: u64,
    /// Receipt node containing the derivation report
    pub receipt_node: u64,
    /// Output node containing the last successful or fallback bytes
    pub output_node: u64,
    /// Related signature nodes created from the output
    pub related_nodes: Vec<u64>,
    /// Typed result for this selected input
    pub state: DecodeItemState,
    /// Work bytes actually charged by the canonical derivation engine
    pub work_bytes: usize,
    /// Whether an operation stopped at its explicit derivation work ceiling
    pub work_budget_exhausted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Created nodes and completion state for one service call
pub struct DecodeOutcome {
    /// Per-input node ids in selected-input order
    pub created_nodes: Vec<DecodeCreatedNodes>,
    /// Whether every candidate completed its derivation and constraints
    pub completeness: DecodeStageCompleteness,
    /// Whether the case carried prior collection omissions
    pub omissions: DecodeOmissionState,
}

impl DecodeOutcome {
    /// Return true when every derivation and the input collection are complete
    pub const fn is_complete(&self) -> bool {
        matches!(self.completeness, DecodeStageCompleteness::Complete)
            && matches!(self.omissions, DecodeOmissionState::None)
    }
}

struct StagedItem {
    input_node: u64,
    output: Vec<u8>,
    receipt: Vec<u8>,
    execution: StagedExecution,
    constraints_satisfied: bool,
    operand_nodes: Vec<u64>,
    work_bytes: usize,
    work_budget_exhausted: bool,
    output_limit_exceeded: Option<usize>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StagedExecution {
    Completed,
    Failed,
    ExecutionError,
}

/// Detached results from one recipe application, before evidence nodes are committed
pub(in crate::workbench) struct PreparedRecipe {
    recipe: derivation::Recipe,
    staged_items: Vec<StagedItem>,
    completeness: DecodeStageCompleteness,
    omissions: DecodeOmissionState,
}

#[derive(Clone, Copy)]
pub(in crate::workbench) struct PreparedItemSummary {
    pub(in crate::workbench) state: DecodeItemState,
    pub(in crate::workbench) work_bytes: usize,
    pub(in crate::workbench) work_budget_exhausted: bool,
    pub(in crate::workbench) output_limit_exceeded: Option<usize>,
}

impl PreparedRecipe {
    pub(in crate::workbench) fn item(&self, index: usize) -> Option<PreparedItemSummary> {
        self.staged_items
            .get(index)
            .map(|item| PreparedItemSummary {
                state: item_state(item),
                work_bytes: item.work_bytes,
                work_budget_exhausted: item.work_budget_exhausted,
                output_limit_exceeded: item.output_limit_exceeded,
            })
    }
}

#[derive(Serialize)]
struct DecodeReceipt<'a> {
    input_node: u64,
    item_index: usize,
    status: ReceiptStatus<'a>,
    input_length: usize,
    input_sha256: &'a str,
    output_length: usize,
    output_sha256: &'a str,
    steps: &'a [StepReport],
    constraints: &'a [ConstraintReport],
    intermediate_bytes: usize,
    work_bytes: usize,
    limits: DerivationLimits,
    batch_limits: DecodeBatchLimits,
    external_acceptance: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_error: Option<&'a str>,
}

#[derive(Clone, Copy, Serialize)]
/// Explicit aggregate limits applied to one decode batch
pub struct DecodeBatchLimits {
    #[serde(rename = "max_items")]
    /// Maximum selected input count
    pub items: usize,
    #[serde(rename = "max_total_input_bytes")]
    /// Maximum bytes across all selected inputs
    pub total_input_bytes: usize,
    #[serde(rename = "max_total_work_bytes")]
    /// Maximum derivation work across the batch
    pub total_work_bytes: usize,
    #[serde(rename = "max_total_output_bytes")]
    /// Maximum retained output bytes across the batch
    pub total_output_bytes: usize,
    #[serde(rename = "max_total_report_bytes")]
    /// Maximum serialized receipt bytes across the batch
    pub total_report_bytes: usize,
}

#[derive(Serialize)]
#[serde(untagged)]
enum ReceiptStatus<'a> {
    Derivation(&'a DerivationStatus),
    Failed(ItemFailureStatus),
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ItemFailureStatus {
    Failed,
}

struct LimitedVecWriter {
    bytes: Vec<u8>,
    remaining: usize,
}

impl LimitedVecWriter {
    const fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            remaining: limit,
        }
    }
}

impl Write for LimitedVecWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other(
                "decode receipts exceed the aggregate report byte budget",
            ));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| io::Error::other("decode receipt allocation failed"))?;
        self.bytes.extend_from_slice(bytes);
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Apply one explicit recipe to selected retained byte nodes
///
/// # Errors
/// Returns an error when selected inputs, runtime limits, report budgets, or case quotas fail
pub fn apply_recipe(
    case: &mut Case,
    selected_nodes: &[u64],
    recipe: &derivation::Recipe,
    limits: DerivationLimits,
    batch_limits: DecodeBatchLimits,
) -> Result<DecodeOutcome, Box<dyn Error>> {
    let prepared = prepare_recipe(case, selected_nodes, recipe, limits, batch_limits)?;
    commit_prepared_recipe(case, prepared)
}

/// Prepare one exact recipe without cloning or changing the retained Case
pub(in crate::workbench) fn prepare_recipe(
    case: &Case,
    selected_nodes: &[u64],
    recipe: &derivation::Recipe,
    limits: DerivationLimits,
    batch_limits: DecodeBatchLimits,
) -> Result<PreparedRecipe, Box<dyn Error>> {
    if selected_nodes.len() > batch_limits.items {
        return Err(format!(
            "decode has {} selected inputs; maximum is {}",
            selected_nodes.len(),
            batch_limits.items
        )
        .into());
    }
    // Resolve all retained inputs before running any recipe step
    let selected_inputs = preflight_inputs(case, selected_nodes, batch_limits)?;
    let budgets = DecodeBudgets {
        per_item: limits,
        batch: batch_limits,
        continue_after_item_error: selected_nodes.len() > 1,
    };
    // Derivation reports decide candidate status without duplicating transform logic
    let staged_items = stage_items(&selected_inputs, recipe, case, budgets)?;
    let failed_items = staged_items
        .iter()
        .filter(|item| item.execution != StagedExecution::Completed)
        .count();
    let rejected_items = staged_items
        .iter()
        .filter(|item| item.execution == StagedExecution::Completed && !item.constraints_satisfied)
        .count();
    let completeness = if failed_items == 0 && rejected_items == 0 {
        DecodeStageCompleteness::Complete
    } else {
        DecodeStageCompleteness::Incomplete {
            failed_items,
            rejected_items,
        }
    };
    let omissions = if case.collection_complete() {
        DecodeOmissionState::None
    } else {
        DecodeOmissionState::ExistingCollectionOmissions
    };
    drop(selected_inputs);

    Ok(PreparedRecipe {
        recipe: recipe.clone(),
        staged_items,
        completeness,
        omissions,
    })
}

/// Commit a prepared recipe to one Case after its work budget is accepted
pub(in crate::workbench) fn commit_prepared_recipe(
    case: &mut Case,
    prepared: PreparedRecipe,
) -> Result<DecodeOutcome, Box<dyn Error>> {
    case.transaction(|case| {
        let created_nodes = record_items(case, prepared.staged_items, &prepared.recipe)?;
        case.add_limitation(decode_limitation(&prepared.recipe))?;
        Ok(DecodeOutcome {
            created_nodes,
            completeness: prepared.completeness,
            omissions: prepared.omissions,
        })
    })
}

const fn item_state(item: &StagedItem) -> DecodeItemState {
    if !matches!(item.execution, StagedExecution::Completed) {
        DecodeItemState::Failed
    } else if !item.constraints_satisfied {
        DecodeItemState::Rejected
    } else {
        DecodeItemState::Completed
    }
}

#[derive(Clone, Copy)]
struct DecodeBudgets {
    per_item: DerivationLimits,
    batch: DecodeBatchLimits,
    continue_after_item_error: bool,
}

#[derive(Default)]
struct BatchUsage {
    work: usize,
    output: usize,
    report: usize,
}

type SelectedInput<'a> = (u64, &'a [u8]);

fn preflight_inputs<'a>(
    case: &'a Case,
    selected_nodes: &[u64],
    limits: DecodeBatchLimits,
) -> Result<Vec<SelectedInput<'a>>, Box<dyn Error>> {
    // Resolve every input and total its bytes before staging any evidence changes
    let mut selected_inputs = Vec::new();
    selected_inputs
        .try_reserve_exact(selected_nodes.len())
        .map_err(|_| "decode input selection allocation failed")?;
    let mut total_input_bytes = 0_usize;
    for input_node in selected_nodes {
        let (_, bytes) = selected::bytes(case, *input_node)?;
        total_input_bytes = total_input_bytes
            .checked_add(bytes.len())
            .ok_or("aggregate decode input byte count overflowed")?;
        if total_input_bytes > limits.total_input_bytes {
            return Err(format!(
                "selected inputs contain {total_input_bytes} bytes; aggregate maximum is {}",
                limits.total_input_bytes
            )
            .into());
        }
        selected_inputs.push((*input_node, bytes));
    }
    Ok(selected_inputs)
}

fn stage_items(
    selected_inputs: &[(u64, &[u8])],
    recipe: &derivation::Recipe,
    case: &Case,
    budgets: DecodeBudgets,
) -> Result<Vec<StagedItem>, Box<dyn Error>> {
    let mut staged_items = Vec::new();
    staged_items
        .try_reserve_exact(selected_inputs.len())
        .map_err(|_| "decode item allocation failed")?;
    let mut usage = BatchUsage::default();
    for (item_index, (input_node, input_bytes)) in selected_inputs.iter().enumerate() {
        staged_items.push(stage_item(
            item_index,
            *input_node,
            input_bytes,
            recipe,
            case,
            budgets,
            &mut usage,
        )?);
    }
    Ok(staged_items)
}

fn stage_item(
    item_index: usize,
    input_node: u64,
    input_bytes: &[u8],
    recipe: &derivation::Recipe,
    case: &Case,
    budgets: DecodeBudgets,
    usage: &mut BatchUsage,
) -> Result<StagedItem, Box<dyn Error>> {
    let remaining_work = budgets
        .batch
        .total_work_bytes
        .checked_sub(usage.work)
        .ok_or("aggregate decode work byte count exceeded its limit")?;
    let mut limits = budgets.per_item;
    // A one-byte allowance permits empty-work recipes after the aggregate is spent
    limits.max_work_bytes = limits.max_work_bytes.min(remaining_work.max(1));
    match derivation::run_with_selected_input(input_node, recipe, case, limits) {
        Ok(report) => stage_report(item_index, input_node, report, limits, budgets.batch, usage),
        Err(error) if budgets.continue_after_item_error => stage_error(
            item_index,
            input_node,
            input_bytes,
            error,
            limits,
            budgets.batch,
            usage,
        ),
        Err(error) => Err(error.into()),
    }
}

fn stage_report(
    item_index: usize,
    input_node: u64,
    report: DerivationReport,
    limits: DerivationLimits,
    batch_limits: DecodeBatchLimits,
    usage: &mut BatchUsage,
) -> Result<StagedItem, Box<dyn Error>> {
    usage.work = add_usage(
        usage.work,
        report.work_bytes,
        batch_limits.total_work_bytes,
        "derivation work",
    )?;
    let output_length = report.output.len();
    usage.output = add_usage(
        usage.output,
        output_length,
        batch_limits.total_output_bytes,
        "derivation outputs",
    )?;
    let execution = match report.status {
        DerivationStatus::Completed => StagedExecution::Completed,
        DerivationStatus::Failed { .. } => StagedExecution::Failed,
    };
    let work_budget_exhausted = report.steps.iter().any(|step| {
        matches!(
            step.status,
            StepStatus::Failed {
                error: StepFailure::WorkBudgetExceeded { .. }
            }
        )
    });
    let output_limit_exceeded = report.steps.iter().find_map(|step| match &step.status {
        StepStatus::Failed {
            error: StepFailure::OutputLimitExceeded { limit },
        } => Some(*limit),
        _ => None,
    });
    let work_bytes = report.work_bytes;
    let constraints_satisfied = report
        .constraints
        .iter()
        .all(|constraint| constraint.status == ConstraintStatus::Satisfied);
    let operand_nodes = report_operand_nodes(&report)?;
    let receipt_data = DecodeReceipt {
        input_node,
        item_index,
        status: ReceiptStatus::Derivation(&report.status),
        input_length: report.input_length,
        input_sha256: &report.input_sha256,
        output_length,
        output_sha256: &report.output_sha256,
        steps: &report.steps,
        constraints: &report.constraints,
        intermediate_bytes: report.intermediate_bytes,
        work_bytes: report.work_bytes,
        limits,
        batch_limits,
        external_acceptance: "not_tested",
        execution_error: None,
    };
    let receipt = encode_receipt(&receipt_data, remaining_report_budget(batch_limits, usage)?)?;
    usage.report = add_usage(
        usage.report,
        receipt.len(),
        batch_limits.total_report_bytes,
        "serialized receipts",
    )?;
    Ok(StagedItem {
        input_node,
        output: report.output,
        receipt,
        execution,
        constraints_satisfied,
        operand_nodes,
        work_bytes,
        work_budget_exhausted,
        output_limit_exceeded,
    })
}

fn stage_error(
    item_index: usize,
    input_node: u64,
    input_bytes: &[u8],
    error: derivation::DerivationError,
    limits: DerivationLimits,
    batch_limits: DecodeBatchLimits,
    usage: &mut BatchUsage,
) -> Result<StagedItem, Box<dyn Error>> {
    let mut fallback = Vec::new();
    fallback
        .try_reserve_exact(input_bytes.len())
        .map_err(|_| "decode fallback output allocation failed")?;
    fallback.extend_from_slice(input_bytes);
    usage.output = add_usage(
        usage.output,
        fallback.len(),
        batch_limits.total_output_bytes,
        "derivation outputs",
    )?;
    let input_sha256 = l2_workbench::sha256(input_bytes);
    let error_text = error.to_string();
    let receipt_data = DecodeReceipt {
        input_node,
        item_index,
        status: ReceiptStatus::Failed(ItemFailureStatus::Failed),
        input_length: input_bytes.len(),
        input_sha256: &input_sha256,
        output_length: fallback.len(),
        output_sha256: &input_sha256,
        steps: &[],
        constraints: &[],
        intermediate_bytes: 0,
        work_bytes: 0,
        limits,
        batch_limits,
        external_acceptance: "not_tested",
        execution_error: Some(&error_text),
    };
    let receipt = encode_receipt(&receipt_data, remaining_report_budget(batch_limits, usage)?)?;
    usage.report = add_usage(
        usage.report,
        receipt.len(),
        batch_limits.total_report_bytes,
        "serialized receipts",
    )?;
    Ok(StagedItem {
        input_node,
        output: fallback,
        receipt,
        execution: StagedExecution::ExecutionError,
        constraints_satisfied: false,
        operand_nodes: Vec::new(),
        work_bytes: 0,
        work_budget_exhausted: false,
        output_limit_exceeded: None,
    })
}

fn remaining_report_budget(
    limits: DecodeBatchLimits,
    usage: &BatchUsage,
) -> Result<usize, Box<dyn Error>> {
    limits
        .total_report_bytes
        .checked_sub(usage.report)
        .ok_or_else(|| "aggregate decode report byte count exceeded its limit".into())
}

fn add_usage(
    current: usize,
    additional: usize,
    maximum: usize,
    label: &str,
) -> Result<usize, Box<dyn Error>> {
    let total = current
        .checked_add(additional)
        .ok_or_else(|| format!("aggregate {label} byte count overflowed"))?;
    if total > maximum {
        return Err(format!("{label} exceed aggregate maximum of {maximum} bytes").into());
    }
    Ok(total)
}

fn record_items(
    case: &mut Case,
    items: Vec<StagedItem>,
    recipe: &derivation::Recipe,
) -> Result<Vec<DecodeCreatedNodes>, Box<dyn Error>> {
    let mut created_nodes = Vec::new();
    created_nodes
        .try_reserve_exact(items.len())
        .map_err(|_| "decode created-node allocation failed")?;
    for (item_index, item) in items.into_iter().enumerate() {
        created_nodes.push(record_item(case, item_index, item, recipe)?);
    }
    Ok(created_nodes)
}

fn record_item(
    case: &mut Case,
    item_index: usize,
    item: StagedItem,
    recipe: &derivation::Recipe,
) -> Result<DecodeCreatedNodes, Box<dyn Error>> {
    let state = item_state(&item);
    let completed = item.execution == StagedExecution::Completed;
    let execution_error = item.execution == StagedExecution::ExecutionError;
    let input_node = item.input_node;
    let receipt_node = case.add_bytes_node(
        "decoding_receipt",
        &item.receipt,
        Vec::new(),
        serde_json::json!({
            "representation":"json_blob",
            "item_index":item_index,
            "operation_completed":completed,
            "constraints_satisfied":item.constraints_satisfied
        }),
    )?;
    let output_node = case.add_bytes_node(
        "decoding_output",
        &item.output,
        Vec::new(),
        serde_json::json!({
            "item_index":item_index,
            "operation_completed":completed,
            "constraints_satisfied":item.constraints_satisfied,
            "external_acceptance":"not_tested"
        }),
    )?;
    // Keep signature observations in the returned node list
    let related_nodes = record_signatures(case, output_node, &item.output)?;
    let status = item_status(
        completed,
        item.constraints_satisfied,
        recipe.constraints.is_empty(),
    );
    case.add_edge(Edge {
        from: item.input_node,
        to: receipt_node,
        relation: "tested_by".to_owned(),
        status,
        reason: if execution_error {
            "The recipe could not be resolved or run for this selected input; the receipt records the error".to_owned()
        } else {
            "Explicit operations and checks were run on these retained input bytes".to_owned()
        },
    })?;
    case.add_edge(Edge {
        from: receipt_node,
        to: output_node,
        relation: "produced".to_owned(),
        status,
        reason: if execution_error {
            "The original selected bytes are retained as fallback output because the recipe could not run".to_owned()
        } else {
            "Output is the last successful step result; failed or skipped steps remain in the receipt".to_owned()
        },
    })?;
    for provider_node in item.operand_nodes {
        case.add_edge(Edge {
            from: provider_node,
            to: receipt_node,
            relation: "supplied_operand".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "A checked byte range from this retained node supplied a recipe operand"
                .to_owned(),
        })?;
    }
    Ok(DecodeCreatedNodes {
        input_node,
        receipt_node,
        output_node,
        related_nodes,
        state,
        work_bytes: item.work_bytes,
        work_budget_exhausted: item.work_budget_exhausted,
    })
}

fn record_signatures(
    case: &mut Case,
    output_node: u64,
    output: &[u8],
) -> Result<Vec<u64>, Box<dyn Error>> {
    let start = case.nodes().len();
    file_signatures::add(case, output_node, output)?;
    let count = case.nodes().len() - start;
    let mut related_nodes = Vec::new();
    related_nodes
        .try_reserve_exact(count)
        .map_err(|_| "decode related-node allocation failed")?;
    related_nodes.extend(case.nodes().iter().skip(start).map(|node| node.id));
    Ok(related_nodes)
}

fn encode_receipt(receipt: &DecodeReceipt<'_>, limit: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = LimitedVecWriter::new(limit);
    serde_json::to_writer(&mut writer, receipt)?;
    Ok(writer.bytes)
}

fn report_operand_nodes(report: &DerivationReport) -> Result<Vec<u64>, Box<dyn Error>> {
    let provenance_count = report
        .steps
        .iter()
        .flat_map(|step| &step.operand_provenance)
        .chain(
            report
                .constraints
                .iter()
                .flat_map(|constraint| &constraint.operand_provenance),
        )
        .count();
    let mut result = Vec::new();
    result
        .try_reserve_exact(provenance_count)
        .map_err(|_| "decode operand edge allocation failed")?;
    for provider in report
        .steps
        .iter()
        .flat_map(|step| &step.operand_provenance)
        .chain(
            report
                .constraints
                .iter()
                .flat_map(|constraint| &constraint.operand_provenance),
        )
        .map(|operand| operand.provider_node)
    {
        if !result.contains(&provider) {
            result.push(provider);
        }
    }
    result.sort_unstable();
    Ok(result)
}

const fn item_status(
    completed: bool,
    constraints_satisfied: bool,
    no_constraints: bool,
) -> EvidenceStatus {
    if !completed {
        EvidenceStatus::Unresolved
    } else if !constraints_satisfied {
        EvidenceStatus::ConstraintFailed
    } else if no_constraints {
        EvidenceStatus::Observed
    } else {
        EvidenceStatus::ConstraintSatisfied
    }
}

fn decode_limitation(recipe: &derivation::Recipe) -> &'static str {
    let has_authenticated_operation = recipe
        .steps
        .iter()
        .any(|operation| matches!(operation, derivation::Operation::AesGcmDecrypt { .. }));
    let has_authenticated_constraint = recipe
        .constraints
        .iter()
        .any(|constraint| matches!(constraint, derivation::Constraint::AesGcm { .. }));
    match (has_authenticated_operation, has_authenticated_constraint) {
        (true, true) => {
            "Explicit AES-GCM decryption operation and constraint results apply only to their supplied key, nonce, and associated data; each receipt records both statuses. Source authenticity and external credential acceptance are not established"
        }
        (true, false) => {
            "An explicit AES-GCM decryption operation releases plaintext only after authentication under its supplied key, nonce, and associated data; each receipt records its status. Source authenticity and external credential acceptance are not established"
        }
        (false, true) => {
            "An explicit AES-GCM constraint, when evaluated, checks authenticated decryption only under its supplied key, nonce, and associated data; each receipt records its status. Source authenticity and external credential acceptance are not established"
        }
        (false, false) => {
            "No authenticated-decryption operation or constraint was supplied; source authenticity and external credential acceptance are not established"
        }
    }
}
