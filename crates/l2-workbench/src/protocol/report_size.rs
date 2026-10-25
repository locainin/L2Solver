//! Logical storage estimates shared by stream extraction and workflow reports

use super::{MessageContext, MessageOrigin, MessageRecord, ProtocolError, StreamTransition};
use std::mem::size_of;

/// Number of ASCII bytes in a lowercase SHA-256 digest
pub const SHA256_HEX_BYTES: usize = 64;

/// Report storage split between observed message bytes and their retained records
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecordStorageEstimate {
    pub message_bytes: usize,
    pub metadata_bytes: usize,
}

impl RecordStorageEstimate {
    /// Total logical storage charged for the supplied records
    pub fn total(self, maximum: usize) -> Result<usize, ProtocolError> {
        add_storage(self.message_bytes, self.metadata_bytes, maximum)
    }
}

/// Estimate records with one formula for parser budgets and workflow receipts
pub fn estimate_records(
    messages: &[MessageRecord],
    transitions: &[StreamTransition],
    maximum: usize,
) -> Result<RecordStorageEstimate, ProtocolError> {
    let mut estimate = RecordStorageEstimate::default();
    for message in messages {
        estimate.message_bytes = add_storage(estimate.message_bytes, message.bytes.len(), maximum)?;
        estimate.metadata_bytes = add_storage(
            estimate.metadata_bytes,
            message_metadata_bytes(
                &message.context,
                message.origins.len(),
                &message.assumption,
                message.sha256.len(),
                maximum,
            )?,
            maximum,
        )?;
    }
    for transition in transitions {
        estimate.metadata_bytes = add_storage(
            estimate.metadata_bytes,
            transition_metadata_bytes(
                &transition.context,
                transition.origins.len(),
                &transition.assumption,
                transition.evidence_sha256.as_ref().map_or(0, String::len),
                maximum,
            )?,
            maximum,
        )?;
    }
    Ok(estimate)
}

/// Estimate the fixed and owned-string storage for a message candidate record
pub fn message_metadata_bytes(
    context: &MessageContext,
    origin_count: usize,
    assumption: &str,
    digest_bytes: usize,
    maximum: usize,
) -> Result<usize, ProtocolError> {
    let origin_bytes = origin_count
        .checked_mul(size_of::<MessageOrigin>())
        .ok_or_else(|| report_limit_error(usize::MAX, maximum))?;
    let context_bytes = context_owned_bytes(context, maximum)?;
    add_all(
        [
            size_of::<MessageRecord>(),
            origin_bytes,
            context_bytes,
            assumption.len(),
            digest_bytes,
        ],
        maximum,
    )
}

/// Estimate the fixed and owned-string storage for one state transition
pub fn transition_metadata_bytes(
    context: &MessageContext,
    origin_count: usize,
    assumption: &str,
    digest_bytes: usize,
    maximum: usize,
) -> Result<usize, ProtocolError> {
    let origin_bytes = origin_count
        .checked_mul(size_of::<MessageOrigin>())
        .ok_or_else(|| report_limit_error(usize::MAX, maximum))?;
    let context_bytes = context_owned_bytes(context, maximum)?;
    add_all(
        [
            size_of::<StreamTransition>(),
            origin_bytes,
            context_bytes,
            assumption.len(),
            digest_bytes,
        ],
        maximum,
    )
}

/// Estimate the owned source and scope strings in a context held outside records
pub fn context_owned_bytes(
    context: &MessageContext,
    maximum: usize,
) -> Result<usize, ProtocolError> {
    add_storage(context.source.len(), context.scope.len(), maximum)
}

fn add_all(values: [usize; 5], maximum: usize) -> Result<usize, ProtocolError> {
    values
        .into_iter()
        .try_fold(0_usize, |total, value| add_storage(total, value, maximum))
}

/// Add logical storage charges within one inclusive byte budget
pub fn add_storage(left: usize, right: usize, maximum: usize) -> Result<usize, ProtocolError> {
    let total = left
        .checked_add(right)
        .ok_or_else(|| report_limit_error(usize::MAX, maximum))?;
    if total > maximum {
        return Err(report_limit_error(total, maximum));
    }
    Ok(total)
}

/// Describe the complete logical charge that exceeded its budget
pub const fn report_limit_error(total: usize, maximum: usize) -> ProtocolError {
    ProtocolError::TotalBytesTooLarge { total, maximum }
}
