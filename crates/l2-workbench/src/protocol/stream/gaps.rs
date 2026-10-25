use super::super::{ProtocolError, StreamTransitionState};
use super::model::{
    CANDIDATE_ASSUMPTION, PendingUnparsedTail, StreamMessageParser, StreamTransition,
};
use super::report_budget::{add_storage, checked_count, report_limit_error};
use crate::protocol::report_size::{SHA256_HEX_BYTES, transition_metadata_bytes};

/// Estimated rows and metadata before any gap evidence is allocated
pub(super) struct GapEstimate {
    pub(super) transition_count: usize,
    pub(super) added_metadata: usize,
}

/// Transitions and observed bytes ready to commit after preflight
pub(super) struct PreparedGap {
    pending: PendingUnparsedTail,
    transitions: Vec<StreamTransition>,
}

impl StreamMessageParser {
    pub(super) fn estimate_gap(&self) -> Result<GapEstimate, ProtocolError> {
        let maximum = self.limits.max_report_bytes;
        let mut tail_count = 0_usize;
        let mut tail_metadata = 0_usize;
        if let Some(pending) = self.pending_unparsed.as_ref() {
            let end = pending
                .start
                .checked_add(pending.bytes.len())
                .ok_or(ProtocolError::StreamOffsetOverflow)?;
            let origin_count = self.map_sources(pending.start, end)?.len();
            for _ in &self.candidates {
                tail_count = checked_count(tail_count, maximum)?;
                tail_metadata = add_storage(
                    tail_metadata,
                    transition_metadata_bytes(
                        &self.context,
                        origin_count,
                        CANDIDATE_ASSUMPTION,
                        SHA256_HEX_BYTES,
                        maximum,
                    )?,
                    maximum,
                )?;
            }
        } else {
            for candidate in self
                .candidates
                .iter()
                .filter(|candidate| candidate.active && !candidate.buffer.is_empty())
            {
                let end = candidate
                    .buffer_start
                    .checked_add(candidate.buffer.len())
                    .ok_or(ProtocolError::StreamOffsetOverflow)?;
                let origin_count = self.map_sources(candidate.buffer_start, end)?.len();
                tail_count = checked_count(tail_count, maximum)?;
                tail_metadata = add_storage(
                    tail_metadata,
                    transition_metadata_bytes(
                        &self.context,
                        origin_count,
                        CANDIDATE_ASSUMPTION,
                        SHA256_HEX_BYTES,
                        maximum,
                    )?,
                    maximum,
                )?;
            }
        }

        let gap_row =
            transition_metadata_bytes(&self.context, 0, CANDIDATE_ASSUMPTION, 0, maximum)?;
        let mut added_metadata = tail_metadata;
        for _ in &self.candidates {
            added_metadata = add_storage(added_metadata, gap_row, maximum)?;
        }
        let transition_count = self
            .candidates
            .len()
            .checked_add(tail_count)
            .ok_or_else(|| report_limit_error(usize::MAX, maximum))?;
        Ok(GapEstimate {
            transition_count,
            added_metadata,
        })
    }

    pub(super) fn finalize_pending_tail(&mut self) -> Result<(), ProtocolError> {
        let Some(pending) = self.pending_unparsed.as_ref() else {
            return Ok(());
        };
        let end = pending
            .start
            .checked_add(pending.bytes.len())
            .ok_or(ProtocolError::StreamOffsetOverflow)?;
        let origin_count = self.map_sources(pending.start, end)?.len();
        let metadata = transition_metadata_bytes(
            &self.context,
            origin_count,
            CANDIDATE_ASSUMPTION,
            SHA256_HEX_BYTES,
            self.limits.max_report_bytes,
        )?
        .checked_mul(self.candidates.len())
        .ok_or_else(|| report_limit_error(usize::MAX, self.limits.max_report_bytes))?;
        let retained_after = self
            .retained_bytes
            .checked_sub(pending.bytes.len())
            .and_then(|size| size.checked_add(metadata))
            .ok_or_else(|| report_limit_error(usize::MAX, self.limits.max_report_bytes))?;
        self.check_retained_budget(retained_after)?;

        // Check the output budget before cloning shared tail metadata
        self.transitions
            .try_reserve(self.candidates.len())
            .map_err(|_| ProtocolError::AllocationFailed)?;
        let transitions = self.shared_tail_transitions(
            StreamTransitionState::UnresolvedTail,
            pending.start,
            end,
            &pending.bytes,
        )?;
        self.transitions.extend(transitions);
        self.pending_unparsed = None;
        self.retained_bytes = retained_after;
        Ok(())
    }

    pub(super) fn prepare_gap(
        &self,
        offset: usize,
        bytes: &[u8],
        transition_count: usize,
    ) -> Result<PreparedGap, ProtocolError> {
        // Keep observed bytes after the gap, while framing stays stopped
        let mut transitions = Vec::new();
        transitions
            .try_reserve_exact(transition_count)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        if let Some(pending) = self.pending_unparsed.as_ref() {
            let end = pending
                .start
                .checked_add(pending.bytes.len())
                .ok_or(ProtocolError::StreamOffsetOverflow)?;
            transitions.extend(self.shared_tail_transitions(
                StreamTransitionState::UnresolvedTail,
                pending.start,
                end,
                &pending.bytes,
            )?);
        } else {
            for (index, candidate) in self.candidates.iter().enumerate() {
                if candidate.active && !candidate.buffer.is_empty() {
                    let end = candidate
                        .buffer_start
                        .checked_add(candidate.buffer.len())
                        .ok_or(ProtocolError::StreamOffsetOverflow)?;
                    transitions.push(self.build_transition(
                        index,
                        StreamTransitionState::UnresolvedTail,
                        candidate.buffer_start,
                        end,
                        Some(&candidate.buffer),
                    )?);
                }
            }
        }
        for index in 0..self.candidates.len() {
            transitions.push(self.build_transition(
                index,
                StreamTransitionState::SequenceGap,
                self.next_offset,
                offset,
                None,
            )?);
        }
        let mut pending_bytes = Vec::new();
        pending_bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| ProtocolError::AllocationFailed)?;
        pending_bytes.extend_from_slice(bytes);
        Ok(PreparedGap {
            pending: PendingUnparsedTail {
                start: offset,
                bytes: pending_bytes,
            },
            transitions,
        })
    }

    pub(super) fn commit_gap(&mut self, gap: PreparedGap, retained_bytes: usize) {
        self.transitions.extend(gap.transitions);
        for candidate in &mut self.candidates {
            // Inactive candidates never reuse their buffered allocation
            candidate.buffer = Vec::new();
            candidate.delimiter_scanned_to = candidate.delimiter_scanned_to.map(|_| 0);
            candidate.active = false;
        }
        self.pending_unparsed = Some(gap.pending);
        self.retained_bytes = retained_bytes;
    }

    fn shared_tail_transitions(
        &self,
        state: StreamTransitionState,
        start: usize,
        end: usize,
        bytes: &[u8],
    ) -> Result<Vec<StreamTransition>, ProtocolError> {
        let mut transitions = Vec::new();
        transitions
            .try_reserve_exact(self.candidates.len())
            .map_err(|_| ProtocolError::AllocationFailed)?;
        let origins = self.map_sources(start, end)?;
        let evidence_sha256 = Some(crate::sha256(bytes));
        for (index, candidate) in self.candidates.iter().enumerate() {
            transitions.push(StreamTransition {
                context: self.context.clone(),
                framing_index: index,
                framing: candidate.framing.clone(),
                generation_ambiguous: self.ambiguity.generation,
                sequence_ambiguous: self.ambiguity.sequence,
                state,
                stream_range: super::super::ByteRange { start, end },
                evidence_sha256: evidence_sha256.clone(),
                origins: origins.clone(),
                role: None,
                assumption: CANDIDATE_ASSUMPTION.to_owned(),
            });
        }
        Ok(transitions)
    }
}
