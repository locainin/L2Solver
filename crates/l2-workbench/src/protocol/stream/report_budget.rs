use super::super::{MessageContext, ProtocolError};
use super::gaps::GapEstimate;
use super::mapping::map_origin_overlap;
use super::model::{CANDIDATE_ASSUMPTION, CandidateState, StreamMessageParser};
use super::origin_index::SourceOriginIndex;
use super::planning::CandidatePlan;
pub(super) use crate::protocol::report_size::{add_storage, report_limit_error};
use crate::{
    protocol::report_size::{
        SHA256_HEX_BYTES, context_owned_bytes, message_metadata_bytes, transition_metadata_bytes,
    },
    reconstruction::Origin,
};

#[derive(Default)]
struct PlanEstimate {
    metadata_bytes: usize,
    released_bytes: usize,
    message_count: usize,
    transition_count: usize,
}

impl StreamMessageParser {
    pub(super) fn plan_candidates(
        &self,
        bytes: &[u8],
    ) -> Result<Vec<CandidatePlan>, ProtocolError> {
        let active_count = self
            .candidates
            .iter()
            .filter(|candidate| candidate.active)
            .count();
        let maximum = self.limits.max_report_bytes;
        let plan_storage = active_count
            .checked_mul(std::mem::size_of::<CandidatePlan>())
            .ok_or_else(|| report_limit_error(usize::MAX, maximum))?;
        if plan_storage > maximum {
            return Err(report_limit_error(plan_storage, maximum));
        }
        let mut plans = Vec::new();
        plans
            .try_reserve_exact(active_count)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        let mut remaining_samples = self.limits.max_samples.saturating_sub(self.messages.len());
        let mut workspace_bytes = plan_storage;
        for (index, candidate) in self.candidates.iter().enumerate() {
            if candidate.active {
                plans.push(super::planning::plan_candidate(
                    index,
                    candidate,
                    bytes,
                    self.limits.max_message_bytes,
                    &mut remaining_samples,
                    &mut workspace_bytes,
                    maximum,
                )?);
            }
        }
        Ok(plans)
    }

    pub(super) fn reserve_chunk_report(
        &mut self,
        bytes: &[u8],
        source_origins: &[Origin],
        gap: Option<&GapEstimate>,
        plans: &[CandidatePlan],
    ) -> Result<usize, ProtocolError> {
        let maximum = self.limits.max_report_bytes;
        // Preflight the exact plan that push_chunk will commit
        let (retained_after, message_count, transition_count) = if let Some(gap) = gap {
            (
                self.retained_after_gap(bytes.len(), gap)?,
                0,
                gap.transition_count,
            )
        } else if self.pending_unparsed.is_some() {
            (
                add_storage(self.retained_bytes, bytes.len(), maximum)?,
                0,
                0,
            )
        } else {
            self.estimate_candidate_plans(plans, bytes.len(), source_origins)?
        };
        // Distinct full source ranges can clip to equal message rows
        let new_origin_count = source_origins
            .iter()
            .filter(|origin| !self.source_origins.contains(origin))
            .count();
        let source_storage = SourceOriginIndex::estimated_storage_bytes(self.source_origins.len())
            .and_then(|current| {
                SourceOriginIndex::estimated_storage_bytes(new_origin_count)
                    .and_then(|incoming| current.checked_add(incoming))
            })
            .ok_or_else(|| report_limit_error(usize::MAX, maximum))?;
        let prospective = retained_after
            .checked_add(source_storage)
            .ok_or_else(|| report_limit_error(usize::MAX, maximum))?;
        if prospective > maximum {
            return Err(report_limit_error(prospective, maximum));
        }

        self.messages
            .try_reserve(message_count)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        self.transitions
            .try_reserve(transition_count)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        if self.pending_unparsed.is_some() && gap.is_none() {
            self.pending_unparsed
                .as_mut()
                .ok_or(ProtocolError::InvalidParserState)?
                .bytes
                .try_reserve(bytes.len())
                .map_err(|_| ProtocolError::AllocationFailed)?;
        } else if gap.is_none() {
            for plan in plans {
                let candidate = self
                    .candidates
                    .get_mut(plan.candidate_index)
                    .ok_or(ProtocolError::InvalidParserState)?;
                candidate
                    .buffer
                    .try_reserve(bytes.len())
                    .map_err(|_| ProtocolError::AllocationFailed)?;
            }
        }
        Ok(retained_after)
    }

    fn estimate_candidate_plans(
        &self,
        plans: &[CandidatePlan],
        chunk_length: usize,
        incoming_origins: &[Origin],
    ) -> Result<(usize, usize, usize), ProtocolError> {
        let maximum = self.limits.max_report_bytes;
        let mut estimate = PlanEstimate::default();
        for plan in plans {
            let candidate = self
                .candidates
                .get(plan.candidate_index)
                .ok_or(ProtocolError::InvalidParserState)?;
            let candidate_estimate =
                self.estimate_candidate_plan(candidate, plan, incoming_origins)?;
            estimate.metadata_bytes = add_storage(
                estimate.metadata_bytes,
                candidate_estimate.metadata_bytes,
                maximum,
            )?;
            estimate.released_bytes = estimate
                .released_bytes
                .checked_add(candidate_estimate.released_bytes)
                .ok_or_else(|| report_limit_error(usize::MAX, maximum))?;
            estimate.message_count = estimate
                .message_count
                .checked_add(candidate_estimate.message_count)
                .ok_or_else(|| report_limit_error(usize::MAX, maximum))?;
            estimate.transition_count = estimate
                .transition_count
                .checked_add(candidate_estimate.transition_count)
                .ok_or_else(|| report_limit_error(usize::MAX, maximum))?;
        }
        let incoming_bytes = chunk_length
            .checked_mul(plans.len())
            .ok_or_else(|| report_limit_error(usize::MAX, maximum))?;
        let retained_after = self
            .retained_bytes
            .checked_add(incoming_bytes)
            .and_then(|size| size.checked_sub(estimate.released_bytes))
            .and_then(|size| size.checked_add(estimate.metadata_bytes))
            .ok_or_else(|| report_limit_error(usize::MAX, maximum))?;
        // The caller checks this charge together with source-index storage
        Ok((
            retained_after,
            estimate.message_count,
            estimate.transition_count,
        ))
    }

    fn estimate_candidate_plan(
        &self,
        candidate: &CandidateState,
        plan: &CandidatePlan,
        incoming_origins: &[Origin],
    ) -> Result<PlanEstimate, ProtocolError> {
        let maximum = self.limits.max_report_bytes;
        let mut estimate = PlanEstimate::default();
        let mut consumed = 0_usize;
        // Count output from the saved boundaries without scanning the bytes again
        for frame_end in &plan.frame_ends {
            let start = absolute_offset(candidate.buffer_start, consumed)?;
            let end = absolute_offset(candidate.buffer_start, *frame_end)?;
            let origins = self.estimated_origin_count(start, end, incoming_origins)?;
            estimate.metadata_bytes = self.add_frame_metadata(estimate.metadata_bytes, origins)?;
            estimate.message_count = checked_count(estimate.message_count, maximum)?;
            estimate.transition_count = checked_count(estimate.transition_count, maximum)?;
            consumed = *frame_end;
        }
        if consumed != plan.consumed {
            return Err(ProtocolError::InvalidParserState);
        }
        if plan.terminal.is_some() {
            let start = absolute_offset(candidate.buffer_start, consumed)?;
            let end = absolute_offset(candidate.buffer_start, plan.combined_length)?;
            let origin_count = self.estimated_origin_count(start, end, incoming_origins)?;
            estimate.metadata_bytes = add_storage(
                estimate.metadata_bytes,
                transition_metadata_bytes(
                    &self.context,
                    origin_count,
                    CANDIDATE_ASSUMPTION,
                    SHA256_HEX_BYTES,
                    maximum,
                )?,
                maximum,
            )?;
            estimate.released_bytes = plan
                .combined_length
                .checked_sub(consumed)
                .ok_or(ProtocolError::InvalidParserState)?;
            estimate.transition_count = checked_count(estimate.transition_count, maximum)?;
        }
        Ok(estimate)
    }

    fn add_frame_metadata(
        &self,
        current: usize,
        origin_count: usize,
    ) -> Result<usize, ProtocolError> {
        let maximum = self.limits.max_report_bytes;
        let message = message_metadata_bytes(
            &self.context,
            origin_count,
            CANDIDATE_ASSUMPTION,
            SHA256_HEX_BYTES,
            maximum,
        )?;
        let boundary = transition_metadata_bytes(
            &self.context,
            origin_count,
            CANDIDATE_ASSUMPTION,
            SHA256_HEX_BYTES,
            maximum,
        )?;
        add_storage(add_storage(current, message, maximum)?, boundary, maximum)
    }

    fn estimated_origin_count(
        &self,
        start: usize,
        end: usize,
        incoming_origins: &[Origin],
    ) -> Result<usize, ProtocolError> {
        let mut count = self
            .source_origins
            .query_overlapping(start, end)
            .map_or(0, Iterator::count);
        for origin in incoming_origins {
            if !self.source_origins.contains(origin)
                && map_origin_overlap(origin, start, end)?.is_some()
            {
                count = checked_count(count, self.limits.max_report_bytes)?;
            }
        }
        Ok(count)
    }

    fn retained_after_gap(
        &self,
        chunk_length: usize,
        gap: &GapEstimate,
    ) -> Result<usize, ProtocolError> {
        let candidate_bytes = self
            .candidates
            .iter()
            .try_fold(0_usize, |total, candidate| {
                total.checked_add(candidate.buffer.len())
            });
        let pending_bytes = self
            .pending_unparsed
            .as_ref()
            .map_or(0, |pending| pending.bytes.len());
        let released = candidate_bytes
            .and_then(|size| size.checked_add(pending_bytes))
            .ok_or_else(|| report_limit_error(usize::MAX, self.limits.max_report_bytes))?;
        let raw_after = self
            .retained_bytes
            .checked_sub(released)
            .and_then(|size| size.checked_add(chunk_length))
            .ok_or_else(|| report_limit_error(usize::MAX, self.limits.max_report_bytes))?;
        add_storage(raw_after, gap.added_metadata, self.limits.max_report_bytes)
    }

    pub(super) fn check_retained_budget(&self, retained: usize) -> Result<(), ProtocolError> {
        let source_storage = SourceOriginIndex::estimated_storage_bytes(self.source_origins.len())
            .ok_or_else(|| report_limit_error(usize::MAX, self.limits.max_report_bytes))?;
        let prospective = retained
            .checked_add(source_storage)
            .ok_or_else(|| report_limit_error(usize::MAX, self.limits.max_report_bytes))?;
        if prospective > self.limits.max_report_bytes {
            return Err(report_limit_error(
                prospective,
                self.limits.max_report_bytes,
            ));
        }
        Ok(())
    }
}

pub(super) fn parser_base_storage(
    context: &MessageContext,
    candidate_count: usize,
    maximum: usize,
) -> Result<usize, ProtocolError> {
    let candidate_storage = candidate_count
        .checked_mul(std::mem::size_of::<CandidateState>())
        .ok_or_else(|| report_limit_error(usize::MAX, maximum))?;
    let fixed_storage = std::mem::size_of::<StreamMessageParser>()
        .checked_add(candidate_storage)
        .ok_or_else(|| report_limit_error(usize::MAX, maximum))?;
    add_storage(
        fixed_storage,
        context_owned_bytes(context, maximum)?,
        maximum,
    )
}

fn absolute_offset(start: usize, relative: usize) -> Result<usize, ProtocolError> {
    start
        .checked_add(relative)
        .ok_or(ProtocolError::StreamOffsetOverflow)
}

pub(super) fn checked_count(count: usize, maximum: usize) -> Result<usize, ProtocolError> {
    count
        .checked_add(1)
        .ok_or_else(|| report_limit_error(usize::MAX, maximum))
}
