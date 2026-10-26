use super::{analysis, evidence};
use crate::arguments::RecordCountSource;
use l2_workbench::{
    evidence::Case,
    protocol::{RecordError, RecordLimits, RecordSchema},
};
use std::error::Error;

const RECORDS_LIMITATION: &str = "Record field meanings and sequence bases are operator supplied; a terminal sequence is also operator supplied and is required to claim a complete object, while observed payload bytes remain available as candidates";

pub struct RecordServiceInput<'a> {
    pub selected_node_ids: &'a [u64],
    pub count_sources: Option<&'a [RecordCountSource]>,
    pub schema: &'a RecordSchema,
    pub limits: RecordLimits,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecordOmissions {
    pub missing_sequences: u128,
    pub duplicate_sequences: usize,
    pub sequences_before_base: usize,
    pub sequences_after_terminal: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordServiceOutcome {
    pub receipt_node_id: u64,
    pub group_node_ids: Vec<u64>,
    pub issue_node_ids: Vec<u64>,
    pub groups_complete: bool,
    pub omissions: RecordOmissions,
}

/// Recovered record outcomes plus exact inputs rejected by the strict parser
pub(in crate::workbench) struct RecoveryRecordServiceOutcome {
    pub(in crate::workbench) outcome: RecordServiceOutcome,
    pub(in crate::workbench) rejected_inputs: Vec<analysis::RejectedInput>,
}

struct CommittedRecordService {
    outcome: RecordServiceOutcome,
    rejected_inputs: Vec<analysis::RejectedInput>,
}

/// Detached record parsing and assembly results before evidence nodes are written
pub(in crate::workbench) struct PreparedRecordService {
    analysis: analysis::Analysis,
    groups_complete: bool,
    omissions: RecordOmissions,
}

impl PreparedRecordService {
    /// Sum the exact receipt and group candidate bytes that commit will retain
    pub(in crate::workbench) fn retained_output_bytes(&self) -> Result<usize, RecordError> {
        self.analysis
            .receipt
            .len()
            .checked_add(self.analysis.assembly.report().output_bytes)
            .ok_or(RecordError::InvalidReport)
    }
}

pub fn apply(
    case: &mut Case,
    input: &RecordServiceInput<'_>,
) -> Result<RecordServiceOutcome, Box<dyn Error>> {
    let prepared = prepare(case, input)?;
    commit(case, prepared)
}

/// Prepare exact records without cloning or changing the retained Case
pub(in crate::workbench) fn prepare(
    case: &Case,
    input: &RecordServiceInput<'_>,
) -> Result<PreparedRecordService, Box<dyn Error>> {
    let analysis = analysis::analyze(
        case,
        input.selected_node_ids,
        input.count_sources,
        input.schema,
        input.limits,
    )?;
    let groups_complete = analysis
        .assembly
        .groups()
        .iter()
        .all(|group| group.receipt().complete);
    let omissions = omissions(&analysis)?;
    Ok(PreparedRecordService {
        analysis,
        groups_complete,
        omissions,
    })
}

/// Prepare sibling inputs independently while keeping aggregate record limits
pub(in crate::workbench) fn prepare_recovery(
    case: &Case,
    input: &RecordServiceInput<'_>,
) -> Result<PreparedRecordService, Box<dyn Error>> {
    let analysis = analysis::analyze_recovery(
        case,
        input.selected_node_ids,
        input.count_sources,
        input.schema,
        input.limits,
    )?;
    let groups_complete = analysis.rejected_inputs.is_empty()
        && analysis
            .assembly
            .groups()
            .iter()
            .all(|group| group.receipt().complete);
    let omissions = omissions(&analysis)?;
    Ok(PreparedRecordService {
        analysis,
        groups_complete,
        omissions,
    })
}

/// Commit prepared exact records after policy checks accept the result
pub(in crate::workbench) fn commit(
    case: &mut Case,
    prepared: PreparedRecordService,
) -> Result<RecordServiceOutcome, Box<dyn Error>> {
    commit_with_rejections(case, prepared).map(|committed| committed.outcome)
}

pub(in crate::workbench) fn commit_recovery(
    case: &mut Case,
    prepared: PreparedRecordService,
) -> Result<RecoveryRecordServiceOutcome, Box<dyn Error>> {
    let committed = commit_with_rejections(case, prepared)?;
    Ok(RecoveryRecordServiceOutcome {
        outcome: committed.outcome,
        rejected_inputs: committed.rejected_inputs,
    })
}

fn commit_with_rejections(
    case: &mut Case,
    prepared: PreparedRecordService,
) -> Result<CommittedRecordService, Box<dyn Error>> {
    let PreparedRecordService {
        analysis,
        groups_complete,
        omissions,
    } = prepared;

    let outcome = case.transaction(|case| {
        let receipt_node_id = evidence::add_receipt_node(case, &analysis)?;
        evidence::add_receipt_edges(case, receipt_node_id, &analysis)?;
        let group_nodes = evidence::record_groups(case, receipt_node_id, &analysis)?;
        case.add_limitation(RECORDS_LIMITATION)?;

        Ok::<_, Box<dyn Error>>(RecordServiceOutcome {
            receipt_node_id,
            group_node_ids: group_nodes.groups,
            issue_node_ids: group_nodes.issues,
            groups_complete,
            omissions,
        })
    })?;
    Ok(CommittedRecordService {
        outcome,
        rejected_inputs: analysis.rejected_inputs,
    })
}

fn omissions(analysis: &analysis::Analysis) -> Result<RecordOmissions, RecordError> {
    analysis
        .assembly
        .groups()
        .iter()
        .try_fold(RecordOmissions::default(), |mut total, group| {
            let receipt = group.receipt();
            total.missing_sequences = total
                .missing_sequences
                .checked_add(receipt.omitted_missing_sequences)
                .ok_or(RecordError::InvalidReport)?;
            total.duplicate_sequences = total
                .duplicate_sequences
                .checked_add(receipt.omitted_duplicate_sequences)
                .ok_or(RecordError::InvalidReport)?;
            total.sequences_before_base = total
                .sequences_before_base
                .checked_add(receipt.omitted_sequences_before_base)
                .ok_or(RecordError::InvalidReport)?;
            total.sequences_after_terminal = total
                .sequences_after_terminal
                .checked_add(receipt.omitted_sequences_after_terminal)
                .ok_or(RecordError::InvalidReport)?;
            Ok(total)
        })
}
