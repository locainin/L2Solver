use super::super::{
    FramingKind, ProtocolError, StreamTransitionState,
    boundaries::{NextBoundary, next_boundary_parts},
};
use super::model::CandidateState;
use super::report_budget::report_limit_error;
use std::mem::size_of;

/// Boundary decisions for one candidate before a chunk changes parser state
pub(super) struct CandidatePlan {
    pub(super) candidate_index: usize,
    pub(super) frame_ends: Vec<usize>,
    pub(super) consumed: usize,
    pub(super) scanned_to: Option<usize>,
    pub(super) terminal: Option<StreamTransitionState>,
    pub(super) combined_length: usize,
}

/// Plan candidate boundaries over the retained prefix and new chunk without joining them
pub(super) fn plan_candidate(
    candidate_index: usize,
    candidate: &CandidateState,
    incoming: &[u8],
    max_message_bytes: usize,
    remaining_samples: &mut usize,
    workspace_bytes: &mut usize,
    maximum_workspace_bytes: usize,
) -> Result<CandidatePlan, ProtocolError> {
    let invalid_state = || ProtocolError::InvalidParserState;
    let combined_length = candidate
        .buffer
        .len()
        .checked_add(incoming.len())
        .ok_or(ProtocolError::StreamOffsetOverflow)?;
    let mut frame_ends = Vec::new();
    let mut consumed = 0_usize;
    let mut scanned_to = candidate.delimiter_scanned_to;
    let mut terminal = None;

    loop {
        let cursor = match &candidate.framing {
            FramingKind::Delimiter { .. } => scanned_to.ok_or_else(invalid_state)?.max(consumed),
            _ => consumed,
        };
        match next_boundary_parts(&candidate.buffer, incoming, cursor, &candidate.framing) {
            NextBoundary::Frame(frame_end) => {
                let message_length = frame_end
                    .checked_sub(consumed)
                    .ok_or(ProtocolError::StreamOffsetOverflow)?;
                if message_length > max_message_bytes || *remaining_samples == 0 {
                    terminal = Some(StreamTransitionState::ResourceOmitted);
                    break;
                }
                let next_workspace = workspace_bytes
                    .checked_add(size_of::<usize>())
                    .ok_or_else(|| report_limit_error(usize::MAX, maximum_workspace_bytes))?;
                if next_workspace > maximum_workspace_bytes {
                    return Err(report_limit_error(next_workspace, maximum_workspace_bytes));
                }
                frame_ends
                    .try_reserve(1)
                    .map_err(|_| ProtocolError::AllocationFailed)?;
                frame_ends.push(frame_end);
                *workspace_bytes = next_workspace;
                *remaining_samples -= 1;
                consumed = frame_end;
                if matches!(&candidate.framing, FramingKind::Delimiter { .. }) {
                    scanned_to = Some(frame_end);
                }
            }
            NextBoundary::Incomplete => {
                let suffix_length = combined_length
                    .checked_sub(consumed)
                    .ok_or(ProtocolError::InvalidParserState)?;
                if suffix_length > max_message_bytes {
                    terminal = Some(StreamTransitionState::ResourceOmitted);
                } else if matches!(&candidate.framing, FramingKind::Delimiter { .. }) {
                    scanned_to = Some(combined_length);
                }
                break;
            }
            NextBoundary::Invalid => {
                terminal = Some(StreamTransitionState::InvalidCandidate);
                break;
            }
        }
    }

    let scanned_to = if terminal.is_some() {
        matches!(&candidate.framing, FramingKind::Delimiter { .. }).then_some(0)
    } else {
        scanned_to
            .map(|offset| {
                offset
                    .checked_sub(consumed)
                    .ok_or(ProtocolError::InvalidParserState)
            })
            .transpose()?
    };
    Ok(CandidatePlan {
        candidate_index,
        frame_ends,
        consumed,
        scanned_to,
        terminal,
        combined_length,
    })
}
