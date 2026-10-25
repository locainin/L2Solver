use super::super::{FramingKind, ProtocolError, sampling::validate_limits};
use super::mapping::{message_origins_cover, source_map_covers};
use super::model::{
    CANDIDATE_ASSUMPTION, CURRENT_CHECKPOINT_VERSION, StreamMessageParser, StreamTransitionState,
};
use super::origin_index::SourceOriginIndex;
use super::parser::validate_stream_framings;
use super::report_budget::parser_base_storage;
use crate::protocol::report_size::estimate_records;
use crate::reconstruction::Origin;

impl StreamMessageParser {
    pub(super) fn validate_state(&mut self) -> Result<(), ProtocolError> {
        if !self.needs_validation {
            return Ok(());
        }
        self.validate_checkpoint_header()?;
        self.migrate_delimiter_scan_offsets()?;
        let source_origins = self.source_origins.iter().collect::<Vec<_>>();
        let raw_bytes = self.validate_candidate_buffers(&source_origins)?;
        let raw_bytes = self.validate_messages(raw_bytes)?;
        let raw_bytes = self.validate_pending_tail(raw_bytes, &source_origins)?;
        if self.checkpoint_version == 0 && raw_bytes != self.retained_bytes {
            return Err(ProtocolError::InvalidParserState);
        }
        self.validate_transitions()?;
        self.validate_lifecycle()?;
        let metadata = estimate_records(
            &self.messages,
            &self.transitions,
            self.limits.max_report_bytes,
        )
        .map_err(|_| ProtocolError::InvalidParserState)?
        .metadata_bytes;
        let base = parser_base_storage(
            &self.context,
            self.candidates.len(),
            self.limits.max_report_bytes,
        )
        .map_err(|_| ProtocolError::InvalidParserState)?;
        let canonical_bytes = base
            .checked_add(raw_bytes)
            .and_then(|size| size.checked_add(metadata))
            .ok_or(ProtocolError::InvalidParserState)?;
        let is_legacy = self.checkpoint_version == 0;
        if !is_legacy && canonical_bytes != self.retained_bytes {
            return Err(ProtocolError::InvalidParserState);
        }
        let source_storage = SourceOriginIndex::estimated_storage_bytes(self.source_origins.len())
            .ok_or(ProtocolError::InvalidParserState)?;
        if canonical_bytes
            .checked_add(source_storage)
            .is_none_or(|bytes| bytes > self.limits.max_report_bytes)
        {
            return Err(ProtocolError::InvalidParserState);
        }
        if is_legacy {
            self.checkpoint_version = CURRENT_CHECKPOINT_VERSION;
            self.retained_bytes = canonical_bytes;
        }
        self.needs_validation = false;
        Ok(())
    }

    fn migrate_delimiter_scan_offsets(&mut self) -> Result<(), ProtocolError> {
        for candidate in &mut self.candidates {
            let FramingKind::Delimiter { byte } = &candidate.framing else {
                if candidate.delimiter_scanned_to.is_some() {
                    return Err(ProtocolError::InvalidParserState);
                }
                continue;
            };
            if candidate.delimiter_scanned_to.is_none() {
                if candidate.buffer.contains(byte) {
                    return Err(ProtocolError::InvalidParserState);
                }
                candidate.delimiter_scanned_to = Some(candidate.buffer.len());
            }
        }
        Ok(())
    }

    fn validate_checkpoint_header(&self) -> Result<(), ProtocolError> {
        let invalid = || ProtocolError::InvalidParserState;
        validate_limits(self.limits).map_err(|_| invalid())?;
        if self.checkpoint_version > CURRENT_CHECKPOINT_VERSION {
            return Err(invalid());
        }
        if self.context.source.is_empty()
            || self.context.scope.is_empty()
            || self.context.session == 0
            || self.candidates.is_empty()
            || self.next_offset < self.total_input_bytes
            || self.total_input_bytes > self.limits.max_run_bytes
            || self.total_input_bytes > self.limits.max_total_bytes
            || self.messages.len() > self.limits.max_samples
        {
            return Err(invalid());
        }
        let has_gap = self
            .transitions
            .iter()
            .any(|transition| transition.state == StreamTransitionState::SequenceGap);
        if self.checkpoint_version == 0 && (self.pending_unparsed.is_some() || has_gap) {
            return Err(invalid());
        }
        let framings = self
            .candidates
            .iter()
            .map(|candidate| candidate.framing.clone())
            .collect::<Vec<_>>();
        validate_stream_framings(&framings, self.limits).map_err(|_| invalid())?;

        if SourceOriginIndex::estimated_storage_bytes(self.source_origins.len()).is_none() {
            return Err(invalid());
        }
        Ok(())
    }

    fn validate_candidate_buffers(
        &self,
        source_origins: &[Origin],
    ) -> Result<usize, ProtocolError> {
        let invalid = || ProtocolError::InvalidParserState;
        let mut retained_bytes = 0_usize;
        for candidate in &self.candidates {
            let end = candidate
                .buffer_start
                .checked_add(candidate.buffer.len())
                .ok_or_else(invalid)?;
            if end > self.next_offset
                || candidate.buffer.len() > self.limits.max_message_bytes
                || (!candidate.active && !candidate.buffer.is_empty())
                || (!candidate.buffer.is_empty()
                    && !source_map_covers(candidate.buffer_start, end, source_origins)
                        .map_err(|_| invalid())?)
            {
                return Err(invalid());
            }
            match (&candidate.framing, candidate.delimiter_scanned_to) {
                (FramingKind::Delimiter { byte }, Some(scanned_to)) => {
                    let scanned_prefix = candidate.buffer.get(..scanned_to).ok_or_else(invalid)?;
                    if scanned_prefix.contains(byte) {
                        return Err(invalid());
                    }
                }
                (FramingKind::Delimiter { .. }, None) | (_, Some(_)) => {
                    return Err(invalid());
                }
                (_, None) => {}
            }
            retained_bytes = retained_bytes
                .checked_add(candidate.buffer.len())
                .ok_or_else(invalid)?;
        }
        Ok(retained_bytes)
    }

    fn validate_messages(&self, mut retained_bytes: usize) -> Result<usize, ProtocolError> {
        let invalid = || ProtocolError::InvalidParserState;
        for message in &self.messages {
            let candidate = self
                .candidates
                .get(message.framing_index)
                .ok_or_else(invalid)?;
            let range_length = message
                .stream_range
                .end
                .checked_sub(message.stream_range.start)
                .ok_or_else(invalid)?;
            if message.context != self.context
                || message.framing != candidate.framing
                || message.generation_ambiguous != self.ambiguity.generation
                || message.sequence_ambiguous != self.ambiguity.sequence
                || message.role.is_some()
                || message.assumption != CANDIDATE_ASSUMPTION
                || message.stream_range.end > self.next_offset
                || message.stream_range.start.checked_add(message.bytes.len())
                    != Some(message.stream_range.end)
                || range_length != message.bytes.len()
                || message.bytes.len() > self.limits.max_message_bytes
                || message.sha256 != crate::sha256(&message.bytes)
                || !message_origins_cover(message.bytes.len(), &message.origins)
                    .map_err(|_| invalid())?
                || message.origins
                    != self
                        .map_sources(message.stream_range.start, message.stream_range.end)
                        .map_err(|_| invalid())?
            {
                return Err(invalid());
            }
            retained_bytes = retained_bytes
                .checked_add(message.bytes.len())
                .ok_or_else(invalid)?;
        }
        Ok(retained_bytes)
    }

    fn validate_pending_tail(
        &self,
        mut retained_bytes: usize,
        source_origins: &[Origin],
    ) -> Result<usize, ProtocolError> {
        let Some(pending) = self.pending_unparsed.as_ref() else {
            if self.has_sequence_gap() && !self.finalized {
                return Err(ProtocolError::InvalidParserState);
            }
            return Ok(retained_bytes);
        };
        let invalid = || ProtocolError::InvalidParserState;
        let end = pending
            .start
            .checked_add(pending.bytes.len())
            .ok_or_else(invalid)?;
        if !self.has_sequence_gap()
            || self.finalized
            || pending.bytes.is_empty()
            || end != self.next_offset
            || !source_map_covers(pending.start, end, source_origins).map_err(|_| invalid())?
            || self
                .candidates
                .iter()
                .any(|candidate| candidate.active || !candidate.buffer.is_empty())
        {
            return Err(invalid());
        }
        retained_bytes = retained_bytes
            .checked_add(pending.bytes.len())
            .ok_or_else(invalid)?;
        Ok(retained_bytes)
    }

    fn validate_transitions(&self) -> Result<(), ProtocolError> {
        let invalid = || ProtocolError::InvalidParserState;
        for transition in &self.transitions {
            let candidate = self
                .candidates
                .get(transition.framing_index)
                .ok_or_else(invalid)?;
            let is_message_boundary = transition.state == StreamTransitionState::MessageBoundary;
            if transition.context != self.context
                || transition.framing != candidate.framing
                || transition.generation_ambiguous != self.ambiguity.generation
                || transition.sequence_ambiguous != self.ambiguity.sequence
                || transition.role.is_some()
                || transition.assumption != CANDIDATE_ASSUMPTION
                || transition.stream_range.start > transition.stream_range.end
                || transition.stream_range.end > self.next_offset
                || ((transition.state == StreamTransitionState::SequenceGap)
                    != transition.evidence_sha256.is_none())
                || (transition.state == StreamTransitionState::SequenceGap
                    && transition.stream_range.start == transition.stream_range.end)
            {
                return Err(invalid());
            }
            if is_message_boundary {
                // Validated message records already cover these exact origin mappings
                continue;
            }
            if transition.evidence_sha256.is_some() {
                if !message_origins_cover(
                    transition.stream_range.end - transition.stream_range.start,
                    &transition.origins,
                )
                .map_err(|_| invalid())?
                    || transition.origins
                        != self
                            .map_sources(transition.stream_range.start, transition.stream_range.end)
                            .map_err(|_| invalid())?
                {
                    return Err(invalid());
                }
            } else if !transition.origins.is_empty() {
                return Err(invalid());
            }
        }
        self.validate_message_boundaries()?;
        Ok(())
    }

    fn has_sequence_gap(&self) -> bool {
        self.transitions
            .iter()
            .any(|transition| transition.state == StreamTransitionState::SequenceGap)
    }

    fn validate_message_boundaries(&self) -> Result<(), ProtocolError> {
        let invalid = || ProtocolError::InvalidParserState;
        let boundary_count = self
            .transitions
            .iter()
            .filter(|transition| transition.state == StreamTransitionState::MessageBoundary)
            .count();
        if boundary_count != self.messages.len() {
            return Err(invalid());
        }

        let mut message_keys = Vec::new();
        message_keys
            .try_reserve_exact(self.messages.len())
            .map_err(|_| ProtocolError::AllocationFailed)?;
        message_keys.extend(self.messages.iter().enumerate().map(|(index, message)| {
            (
                message.framing_index,
                message.stream_range.start,
                message.stream_range.end,
                index,
            )
        }));
        message_keys.sort_unstable_by_key(|message| (message.0, message.1, message.2));

        let mut matched_messages = Vec::new();
        matched_messages
            .try_reserve_exact(self.messages.len())
            .map_err(|_| ProtocolError::AllocationFailed)?;
        matched_messages.resize(self.messages.len(), false);
        for transition in self
            .transitions
            .iter()
            .filter(|transition| transition.state == StreamTransitionState::MessageBoundary)
        {
            let transition_key = (
                transition.framing_index,
                transition.stream_range.start,
                transition.stream_range.end,
            );
            let message_position = message_keys
                .binary_search_by_key(&transition_key, |message| (message.0, message.1, message.2))
                .map_err(|_| invalid())?;
            let message_index = message_keys
                .get(message_position)
                .map(|message| message.3)
                .ok_or_else(invalid)?;
            let message = self.messages.get(message_index).ok_or_else(invalid)?;
            let matched = matched_messages
                .get_mut(message_index)
                .ok_or_else(invalid)?;
            if *matched
                || transition.evidence_sha256.as_deref() != Some(message.sha256.as_str())
                || transition.origins != message.origins
            {
                return Err(invalid());
            }
            *matched = true;
        }
        if matched_messages.iter().any(|matched| !matched) {
            return Err(invalid());
        }
        Ok(())
    }
}
