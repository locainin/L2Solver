use super::super::{
    ByteRange, FramingKind, MessageContext, ProtocolError, ProtocolLimits,
    sampling::validate_limits,
};
use super::gaps::PreparedGap;
use super::mapping::collect_source_origins;
use super::model::{
    CANDIDATE_ASSUMPTION, CURRENT_CHECKPOINT_VERSION, CandidateState, MessageRecord,
    StreamAmbiguity, StreamExtractionReport, StreamMessageParser, StreamTransition,
    StreamTransitionState,
};
use super::origin_index::SourceOriginIndex;
use super::planning::CandidatePlan;
use super::report_budget::{add_storage, parser_base_storage};
use crate::protocol::report_size::{
    SHA256_HEX_BYTES, message_metadata_bytes, transition_metadata_bytes,
};
use crate::reconstruction::Origin;

struct PreparedChunk {
    end: usize,
    total_input_bytes: usize,
    source_origins: Vec<Origin>,
    gap: Option<PreparedGap>,
    append_pending: bool,
    retained_bytes_after: usize,
    candidate_plans: Vec<CandidatePlan>,
}

impl StreamMessageParser {
    /// Start a parser with competing caller-selected framing interpretations
    ///
    /// Offsets are relative to the reconstructed stream and begin at zero
    ///
    /// # Errors
    /// Rejects invalid context, candidates, or budgets
    pub fn new(
        context: MessageContext,
        generation_ambiguous: bool,
        sequence_ambiguous: bool,
        framings: Vec<FramingKind>,
        limits: ProtocolLimits,
    ) -> Result<Self, ProtocolError> {
        validate_limits(limits)?;
        if context.source.is_empty() || context.scope.is_empty() || context.session == 0 {
            return Err(ProtocolError::InvalidContext {
                sample: context.session,
            });
        }
        validate_stream_framings(&framings, limits)?;
        let mut states = Vec::with_capacity(framings.len());
        for framing in framings {
            let delimiter_scanned_to =
                matches!(framing, FramingKind::Delimiter { .. }).then_some(0);
            states.push(CandidateState {
                framing,
                active: true,
                buffer_start: 0,
                buffer: Vec::new(),
                delimiter_scanned_to,
            });
        }
        let retained_bytes = parser_base_storage(&context, states.len(), limits.max_report_bytes)?;
        Ok(Self {
            context,
            ambiguity: StreamAmbiguity {
                generation: generation_ambiguous,
                sequence: sequence_ambiguous,
            },
            limits,
            candidates: states,
            source_origins: SourceOriginIndex::default(),
            messages: Vec::new(),
            transitions: Vec::new(),
            next_offset: 0,
            total_input_bytes: 0,
            retained_bytes,
            checkpoint_version: CURRENT_CHECKPOINT_VERSION,
            pending_unparsed: None,
            omitted_candidates: 0,
            finalized: false,
            needs_validation: false,
        })
    }

    /// Append the next contiguous reconstructed byte chunk and its source ranges
    ///
    /// A sequence discontinuity is retained as a transition and stops all
    /// candidates because no boundary can be assigned safely after missing bytes
    ///
    /// # Errors
    /// Rejects invalid source maps, offsets, or configured resource budgets
    /// Input byte limits are checked before inspecting the incoming source map
    /// An interrupted commit is validated before a later operation can reuse it
    pub fn push_chunk(
        &mut self,
        offset: usize,
        bytes: &[u8],
        origins: &[Origin],
    ) -> Result<(), ProtocolError> {
        self.validate_state()?;
        if self.finalized {
            return Err(ProtocolError::ParserFinalized);
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let prepared = self.prepare_chunk(offset, bytes, origins)?;
        // A later record allocation can fail after earlier records have committed
        self.needs_validation = true;
        for origin in &prepared.source_origins {
            self.source_origins.insert(origin)?;
        }
        self.next_offset = prepared.end;
        self.total_input_bytes = prepared.total_input_bytes;
        if let Some(gap) = prepared.gap {
            self.commit_gap(gap, prepared.retained_bytes_after);
        } else if prepared.append_pending {
            let pending = self
                .pending_unparsed
                .as_mut()
                .ok_or(ProtocolError::InvalidParserState)?;
            pending.bytes.extend_from_slice(bytes);
            self.retained_bytes = prepared.retained_bytes_after;
        } else {
            for plan in prepared.candidate_plans {
                self.apply_candidate_plan(bytes, plan)?;
            }
            debug_assert_eq!(self.retained_bytes, prepared.retained_bytes_after);
        }
        self.needs_validation = false;
        Ok(())
    }

    fn prepare_chunk(
        &mut self,
        offset: usize,
        bytes: &[u8],
        origins: &[Origin],
    ) -> Result<PreparedChunk, ProtocolError> {
        let end = offset
            .checked_add(bytes.len())
            .ok_or(ProtocolError::StreamOffsetOverflow)?;
        if offset < self.next_offset {
            return Err(ProtocolError::OutOfOrderChunk {
                offset,
                next_offset: self.next_offset,
            });
        }
        // Reject oversized chunks before source-map validation or Origin copies
        let total_input_bytes = self.next_input_length(bytes.len())?;
        let source_origins = collect_source_origins(offset, end, origins)?;
        let gap_estimate = if offset > self.next_offset {
            // Preflight durable rows before copying the newly observed tail
            Some(self.estimate_gap()?)
        } else {
            None
        };
        let append_pending = self.pending_unparsed.is_some() && gap_estimate.is_none();
        let candidate_plans = if gap_estimate.is_none() && !append_pending {
            self.plan_candidates(bytes)?
        } else {
            Vec::new()
        };
        let retained_bytes_after = self.reserve_chunk_report(
            bytes,
            &source_origins,
            gap_estimate.as_ref(),
            &candidate_plans,
        )?;
        let gap = gap_estimate
            .as_ref()
            .map(|estimate| self.prepare_gap(offset, bytes, estimate.transition_count))
            .transpose()?;
        Ok(PreparedChunk {
            end,
            total_input_bytes,
            source_origins,
            gap,
            append_pending,
            retained_bytes_after,
            candidate_plans,
        })
    }

    fn next_input_length(&self, chunk_length: usize) -> Result<usize, ProtocolError> {
        let total = self.total_input_bytes.checked_add(chunk_length).ok_or(
            ProtocolError::TotalBytesTooLarge {
                total: usize::MAX,
                maximum: self.limits.max_run_bytes,
            },
        )?;
        if total > self.limits.max_run_bytes {
            return Err(ProtocolError::RunTooLarge {
                sample: self.context.session,
                length: total,
                maximum: self.limits.max_run_bytes,
            });
        }
        if total > self.limits.max_total_bytes {
            return Err(ProtocolError::TotalBytesTooLarge {
                total,
                maximum: self.limits.max_total_bytes,
            });
        }
        Ok(total)
    }

    /// Retain incomplete candidate tails and close this parser
    ///
    /// # Errors
    /// Returns an error only when serialized evidence cannot be represented
    pub fn finalize(&mut self) -> Result<(), ProtocolError> {
        self.validate_state()?;
        if self.finalized {
            return Ok(());
        }
        if self.pending_unparsed.is_some() {
            self.finalize_pending_tail()?;
            self.finalized = true;
            return Ok(());
        }
        let transition_count = self
            .candidates
            .iter()
            .filter(|state| state.active && !state.buffer.is_empty())
            .count();
        let mut added_metadata = 0_usize;
        for state in self
            .candidates
            .iter()
            .filter(|state| state.active && !state.buffer.is_empty())
        {
            let end = state
                .buffer_start
                .checked_add(state.buffer.len())
                .ok_or(ProtocolError::StreamOffsetOverflow)?;
            let origin_count = self.map_sources(state.buffer_start, end)?.len();
            added_metadata = add_storage(
                added_metadata,
                transition_metadata_bytes(
                    &self.context,
                    origin_count,
                    CANDIDATE_ASSUMPTION,
                    SHA256_HEX_BYTES,
                    self.limits.max_report_bytes,
                )?,
                self.limits.max_report_bytes,
            )?;
        }
        let retained_after = add_storage(
            self.retained_bytes,
            added_metadata,
            self.limits.max_report_bytes,
        )?;
        self.check_retained_budget(retained_after)?;
        self.transitions
            .try_reserve(transition_count)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        let mut tails = Vec::new();
        tails
            .try_reserve_exact(transition_count)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        for index in 0..self.candidates.len() {
            let Some(state) = self.candidates.get(index) else {
                continue;
            };
            if state.active && !state.buffer.is_empty() {
                let start = state.buffer_start;
                let end = start
                    .checked_add(state.buffer.len())
                    .ok_or(ProtocolError::StreamOffsetOverflow)?;
                tails.push(self.build_transition(
                    index,
                    StreamTransitionState::UnresolvedTail,
                    start,
                    end,
                    Some(&state.buffer),
                )?);
            }
        }
        self.transitions.extend(tails);
        self.retained_bytes = retained_after;
        self.finalized = true;
        Ok(())
    }

    /// Consume the parser into a complete extraction report
    ///
    /// # Errors
    /// Returns an error when an incomplete tail cannot be represented
    pub fn into_report(mut self) -> Result<StreamExtractionReport, ProtocolError> {
        self.finalize()?;
        let partial = self.omitted_candidates != 0
            || self.transitions.iter().any(|transition| {
                matches!(
                    transition.state,
                    StreamTransitionState::SequenceGap
                        | StreamTransitionState::UnresolvedTail
                        | StreamTransitionState::InvalidCandidate
                        | StreamTransitionState::ResourceOmitted
                )
            });
        Ok(StreamExtractionReport {
            context: self.context,
            generation_ambiguous: self.ambiguity.generation,
            sequence_ambiguous: self.ambiguity.sequence,
            messages: self.messages,
            transitions: self.transitions,
            input_bytes: self.total_input_bytes,
            omitted_candidates: self.omitted_candidates,
            partial,
        })
    }

    fn apply_candidate_plan(
        &mut self,
        bytes: &[u8],
        plan: CandidatePlan,
    ) -> Result<(), ProtocolError> {
        let chunk_start = self
            .next_offset
            .checked_sub(bytes.len())
            .ok_or(ProtocolError::StreamOffsetOverflow)?;
        let state = self
            .candidates
            .get_mut(plan.candidate_index)
            .ok_or(ProtocolError::InvalidFramingCandidate)?;
        if state.buffer.is_empty() {
            state.buffer_start = chunk_start;
        }
        state.buffer.extend_from_slice(bytes);
        if state.buffer.len() != plan.combined_length {
            return Err(ProtocolError::InvalidParserState);
        }
        self.retained_bytes = self.retained_bytes.checked_add(bytes.len()).ok_or(
            ProtocolError::TotalBytesTooLarge {
                total: usize::MAX,
                maximum: self.limits.max_report_bytes,
            },
        )?;
        let mut consumed = 0;
        for frame_end in plan.frame_ends {
            self.record_message(plan.candidate_index, consumed, frame_end)?;
            consumed = frame_end;
        }
        if consumed != plan.consumed {
            return Err(ProtocolError::InvalidParserState);
        }
        if let Some(scanned_to) = plan.scanned_to {
            let scanned_before_compaction = scanned_to
                .checked_add(consumed)
                .ok_or(ProtocolError::StreamOffsetOverflow)?;
            let state = self
                .candidates
                .get_mut(plan.candidate_index)
                .ok_or(ProtocolError::InvalidFramingCandidate)?;
            state.delimiter_scanned_to = Some(scanned_before_compaction);
        }
        self.compact_candidate(plan.candidate_index, consumed)?;
        if let Some(reason) = plan.terminal {
            let omitted_after = if reason == StreamTransitionState::ResourceOmitted {
                Some(self.omitted_candidates.checked_add(1).ok_or(
                    ProtocolError::TotalBytesTooLarge {
                        total: usize::MAX,
                        maximum: self.limits.max_report_bytes,
                    },
                )?)
            } else {
                None
            };
            self.stop_candidate(plan.candidate_index, reason)?;
            if let Some(omitted) = omitted_after {
                self.omitted_candidates = omitted;
            }
        } else if let Some(state) = self.candidates.get_mut(plan.candidate_index) {
            state.delimiter_scanned_to = plan.scanned_to;
        } else {
            return Err(ProtocolError::InvalidFramingCandidate);
        }
        Ok(())
    }

    fn record_message(
        &mut self,
        index: usize,
        consumed: usize,
        frame_end: usize,
    ) -> Result<(), ProtocolError> {
        let (message, transition) = self.build_message_records(index, consumed, frame_end)?;
        let metadata = add_storage(
            message_metadata_bytes(
                &message.context,
                message.origins.len(),
                &message.assumption,
                message.sha256.len(),
                self.limits.max_report_bytes,
            )?,
            transition_metadata_bytes(
                &transition.context,
                transition.origins.len(),
                &transition.assumption,
                transition.evidence_sha256.as_ref().map_or(0, String::len),
                self.limits.max_report_bytes,
            )?,
            self.limits.max_report_bytes,
        )?;
        let retained_after =
            add_storage(self.retained_bytes, metadata, self.limits.max_report_bytes)?;
        self.messages
            .try_reserve(1)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        self.transitions
            .try_reserve(1)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        self.transitions.push(transition);
        self.messages.push(message);
        self.retained_bytes = retained_after;
        Ok(())
    }

    fn build_message_records(
        &self,
        index: usize,
        consumed: usize,
        frame_end: usize,
    ) -> Result<(MessageRecord, StreamTransition), ProtocolError> {
        let state = self
            .candidates
            .get(index)
            .ok_or(ProtocolError::InvalidFramingCandidate)?;
        let start = state
            .buffer_start
            .checked_add(consumed)
            .ok_or(ProtocolError::StreamOffsetOverflow)?;
        let end = state
            .buffer_start
            .checked_add(frame_end)
            .ok_or(ProtocolError::StreamOffsetOverflow)?;
        let source = state
            .buffer
            .get(consumed..frame_end)
            .ok_or(ProtocolError::InvalidFramingCandidate)?;
        let mut bytes = Vec::new();
        #[cfg(test)]
        allocation_tests::check_message_reservation()?;
        bytes
            .try_reserve_exact(source.len())
            .map_err(|_| ProtocolError::AllocationFailed)?;
        bytes.extend_from_slice(source);
        let origins = self.map_sources(start, end)?;
        let framing = self
            .candidates
            .get(index)
            .ok_or(ProtocolError::InvalidFramingCandidate)?
            .framing
            .clone();
        let sha256 = crate::sha256(&bytes);
        let range = ByteRange { start, end };
        let message = MessageRecord {
            context: self.context.clone(),
            framing_index: index,
            framing: framing.clone(),
            generation_ambiguous: self.ambiguity.generation,
            sequence_ambiguous: self.ambiguity.sequence,
            stream_range: range,
            bytes,
            sha256: sha256.clone(),
            origins: origins.clone(),
            role: None,
            assumption: CANDIDATE_ASSUMPTION.to_owned(),
        };
        let transition = StreamTransition {
            context: self.context.clone(),
            framing_index: index,
            framing,
            generation_ambiguous: self.ambiguity.generation,
            sequence_ambiguous: self.ambiguity.sequence,
            state: StreamTransitionState::MessageBoundary,
            stream_range: range,
            evidence_sha256: Some(sha256),
            origins,
            role: None,
            assumption: CANDIDATE_ASSUMPTION.to_owned(),
        };
        Ok((message, transition))
    }

    fn compact_candidate(&mut self, index: usize, consumed: usize) -> Result<(), ProtocolError> {
        if consumed == 0 {
            return Ok(());
        }
        let state = self
            .candidates
            .get_mut(index)
            .ok_or(ProtocolError::InvalidFramingCandidate)?;
        if let Some(scanned_to) = &mut state.delimiter_scanned_to {
            *scanned_to = scanned_to
                .checked_sub(consumed)
                .ok_or(ProtocolError::InvalidParserState)?;
        }
        state.buffer.drain(..consumed);
        state.buffer_start = state
            .buffer_start
            .checked_add(consumed)
            .ok_or(ProtocolError::StreamOffsetOverflow)?;
        Ok(())
    }

    fn stop_candidate(
        &mut self,
        index: usize,
        reason: StreamTransitionState,
    ) -> Result<(), ProtocolError> {
        let transition = {
            let state = self
                .candidates
                .get(index)
                .ok_or(ProtocolError::InvalidFramingCandidate)?;
            let end = state
                .buffer_start
                .checked_add(state.buffer.len())
                .ok_or(ProtocolError::StreamOffsetOverflow)?;
            self.build_transition(index, reason, state.buffer_start, end, Some(&state.buffer))?
        };
        self.add_transition_record(transition)?;
        let state = self
            .candidates
            .get_mut(index)
            .ok_or(ProtocolError::InvalidFramingCandidate)?;
        self.retained_bytes = self
            .retained_bytes
            .checked_sub(state.buffer.len())
            .ok_or(ProtocolError::InvalidParserState)?;
        state.buffer = Vec::new();
        state.delimiter_scanned_to = state.delimiter_scanned_to.map(|_| 0);
        state.active = false;
        Ok(())
    }

    pub(super) fn build_transition(
        &self,
        index: usize,
        state: StreamTransitionState,
        start: usize,
        end: usize,
        bytes: Option<&[u8]>,
    ) -> Result<StreamTransition, ProtocolError> {
        let candidate = self
            .candidates
            .get(index)
            .ok_or(ProtocolError::InvalidFramingCandidate)?;
        let (evidence_sha256, origins) = match bytes {
            Some(bytes) => (Some(crate::sha256(bytes)), self.map_sources(start, end)?),
            None => (None, Vec::new()),
        };
        Ok(StreamTransition {
            context: self.context.clone(),
            framing_index: index,
            framing: candidate.framing.clone(),
            generation_ambiguous: self.ambiguity.generation,
            sequence_ambiguous: self.ambiguity.sequence,
            state,
            stream_range: ByteRange { start, end },
            evidence_sha256,
            origins,
            role: None,
            assumption: CANDIDATE_ASSUMPTION.to_owned(),
        })
    }

    fn add_transition_record(&mut self, transition: StreamTransition) -> Result<(), ProtocolError> {
        let retained_after = add_storage(
            self.retained_bytes,
            transition_metadata_bytes(
                &transition.context,
                transition.origins.len(),
                &transition.assumption,
                transition.evidence_sha256.as_ref().map_or(0, String::len),
                self.limits.max_report_bytes,
            )?,
            self.limits.max_report_bytes,
        )?;
        self.check_retained_budget(retained_after)?;
        self.transitions
            .try_reserve(1)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        self.transitions.push(transition);
        self.retained_bytes = retained_after;
        Ok(())
    }
}

pub fn validate_stream_framings(
    framings: &[FramingKind],
    limits: ProtocolLimits,
) -> Result<(), ProtocolError> {
    if framings.is_empty() {
        return Err(ProtocolError::NoFramingCandidates);
    }
    if framings.len() > limits.max_candidates {
        return Err(ProtocolError::TooManyCandidates {
            count: framings.len(),
            maximum: limits.max_candidates,
        });
    }
    if framings.iter().enumerate().any(|(index, framing)| {
        invalid_framing(framing, limits.max_message_bytes)
            || framings
                .get(..index)
                .is_some_and(|prior| prior.contains(framing))
    }) {
        return Err(ProtocolError::InvalidFramingCandidate);
    }
    Ok(())
}

const fn invalid_framing(framing: &FramingKind, max_message_bytes: usize) -> bool {
    match framing {
        FramingKind::Delimiter { .. } => false,
        FramingKind::FixedSize { bytes } => *bytes == 0 || *bytes > max_message_bytes,
        FramingKind::LengthPrefix { offset, width, .. } => {
            !matches!(width, 1 | 2 | 4 | 8)
                || offset.checked_add(*width).is_none()
                || offset.saturating_add(*width) > max_message_bytes
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/protocol/stream/allocation.rs"]
mod allocation_tests;
