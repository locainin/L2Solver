use super::super::{
    ProtocolError,
    boundaries::{NextBoundary, next_boundary},
};
use super::model::{CandidateState, StreamMessageParser, StreamTransition, StreamTransitionState};

type Interval = (usize, usize);

impl StreamMessageParser {
    /// Check that candidate records and global gaps form one consistent lifecycle
    pub(super) fn validate_lifecycle(&self) -> Result<(), ProtocolError> {
        let gaps = self.gap_ranges()?;
        self.validate_input_count(&gaps)?;
        self.validate_omitted_count()?;
        self.validate_transition_digest_shapes()?;
        self.validate_message_framings()?;
        self.validate_pending_tail_lifecycle(&gaps)?;

        for (index, candidate) in self.candidates.iter().enumerate() {
            let last_message_end = self.last_message_end(index)?;
            let terminal = self.terminal_transition(index)?;
            if let Some(first_gap) = gaps.first() {
                self.validate_gappy_candidate(
                    index,
                    candidate,
                    last_message_end,
                    terminal,
                    *first_gap,
                )?;
            } else {
                self.validate_contiguous_candidate(index, candidate, last_message_end, terminal)?;
            }
        }

        self.validate_post_gap_tails(&gaps)
    }

    fn gap_ranges(&self) -> Result<Vec<Interval>, ProtocolError> {
        let invalid = || ProtocolError::InvalidParserState;
        // Sequence-gap rows repeat for competing framings but represent one missing interval
        let gap_count = self
            .transitions
            .iter()
            .filter(|transition| transition.state == StreamTransitionState::SequenceGap)
            .count();
        if gap_count == 0 {
            return Ok(Vec::new());
        }

        let mut rows = Vec::new();
        rows.try_reserve_exact(gap_count)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        rows.extend(
            self.transitions
                .iter()
                .filter(|transition| transition.state == StreamTransitionState::SequenceGap)
                .map(|transition| {
                    (
                        transition.stream_range.start,
                        transition.stream_range.end,
                        transition.framing_index,
                    )
                }),
        );
        rows.sort_unstable();

        let mut gaps = Vec::new();
        gaps.try_reserve_exact(gap_count / self.candidates.len())
            .map_err(|_| ProtocolError::AllocationFailed)?;
        let mut row_start = 0;
        while row_start < rows.len() {
            let first = rows.get(row_start).ok_or_else(invalid)?;
            let gap_start = first.0;
            let gap_end = first.1;
            let range = (gap_start, gap_end);
            let mut row_end = row_start + 1;
            while rows.get(row_end).is_some_and(|row| (row.0, row.1) == range) {
                row_end += 1;
            }
            let range_rows = rows.get(row_start..row_end).ok_or_else(invalid)?;
            if gap_start >= gap_end
                || gap_end > self.next_offset
                || range_rows.len() != self.candidates.len()
                || range_rows
                    .iter()
                    .enumerate()
                    .any(|(index, row)| row.2 != index)
                || gaps
                    .last()
                    .is_some_and(|previous: &Interval| previous.1 >= gap_start)
            {
                return Err(invalid());
            }
            gaps.push(range);
            row_start = row_end;
        }
        Ok(gaps)
    }

    fn validate_input_count(&self, gaps: &[Interval]) -> Result<(), ProtocolError> {
        let invalid = || ProtocolError::InvalidParserState;
        // Gap offsets are missing bytes, so they do not contribute to observed input
        let missing = gaps.iter().try_fold(0_usize, |total, (start, end)| {
            total.checked_add(end.checked_sub(*start)?)
        });
        let expected = missing.and_then(|missing| self.next_offset.checked_sub(missing));
        if expected != Some(self.total_input_bytes) {
            return Err(invalid());
        }
        Ok(())
    }

    fn validate_omitted_count(&self) -> Result<(), ProtocolError> {
        let omitted = self
            .transitions
            .iter()
            .filter(|transition| transition.state == StreamTransitionState::ResourceOmitted)
            .count();
        if omitted != self.omitted_candidates {
            return Err(ProtocolError::InvalidParserState);
        }
        Ok(())
    }

    fn validate_transition_digest_shapes(&self) -> Result<(), ProtocolError> {
        // This checks digest spelling only; cleared historical bytes cannot be rehashed here
        if self.transitions.iter().any(|transition| {
            transition
                .evidence_sha256
                .as_deref()
                .is_some_and(|digest| !crate::hashing::is_sha256_digest(digest))
        }) {
            return Err(ProtocolError::InvalidParserState);
        }
        Ok(())
    }

    fn validate_message_framings(&self) -> Result<(), ProtocolError> {
        let invalid = || ProtocolError::InvalidParserState;
        // A matching digest alone cannot establish that the declared framing ends at this boundary
        for message in &self.messages {
            if !matches!(
                next_boundary(&message.bytes, 0, &message.framing),
                NextBoundary::Frame(end) if end == message.bytes.len()
            ) {
                return Err(invalid());
            }
        }
        for candidate in self.candidates.iter().filter(|candidate| candidate.active) {
            if !matches!(
                next_boundary(&candidate.buffer, 0, &candidate.framing),
                NextBoundary::Incomplete
            ) {
                return Err(invalid());
            }
        }
        Ok(())
    }

    fn validate_pending_tail_lifecycle(&self, gaps: &[Interval]) -> Result<(), ProtocolError> {
        let invalid = || ProtocolError::InvalidParserState;
        let Some(last_gap) = gaps.last() else {
            if self.pending_unparsed.is_some() {
                return Err(invalid());
            }
            return Ok(());
        };

        if self.finalized {
            if self.pending_unparsed.is_some() {
                return Err(invalid());
            }
            return Ok(());
        }

        let pending = self.pending_unparsed.as_ref().ok_or_else(invalid)?;
        if pending.bytes.is_empty()
            || pending.start != last_gap.1
            || pending.start.checked_add(pending.bytes.len()) != Some(self.next_offset)
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn last_message_end(&self, framing_index: usize) -> Result<usize, ProtocolError> {
        let invalid = || ProtocolError::InvalidParserState;
        let mut end = 0;
        for message in self
            .messages
            .iter()
            .filter(|message| message.framing_index == framing_index)
        {
            if message.stream_range.start != end {
                return Err(invalid());
            }
            end = message.stream_range.end;
        }
        Ok(end)
    }

    fn terminal_transition(
        &self,
        framing_index: usize,
    ) -> Result<Option<&StreamTransition>, ProtocolError> {
        let mut terminal = None;
        for transition in self.transitions.iter().filter(|transition| {
            transition.framing_index == framing_index
                && matches!(
                    transition.state,
                    StreamTransitionState::InvalidCandidate
                        | StreamTransitionState::ResourceOmitted
                )
        }) {
            if terminal.replace(transition).is_some() {
                return Err(ProtocolError::InvalidParserState);
            }
        }
        Ok(terminal)
    }

    fn candidate_tails(&self, framing_index: usize) -> impl Iterator<Item = &StreamTransition> {
        self.transitions.iter().filter(move |transition| {
            transition.framing_index == framing_index
                && transition.state == StreamTransitionState::UnresolvedTail
        })
    }

    fn validate_contiguous_candidate(
        &self,
        framing_index: usize,
        candidate: &CandidateState,
        last_message_end: usize,
        terminal: Option<&StreamTransition>,
    ) -> Result<(), ProtocolError> {
        let invalid = || ProtocolError::InvalidParserState;
        let mut tails = self.candidate_tails(framing_index);
        let tail = tails.next();
        if tails.next().is_some() {
            return Err(invalid());
        }

        if candidate.active {
            // The active suffix closes the range from the last message end through next_offset
            let buffer_end = candidate
                .buffer_start
                .checked_add(candidate.buffer.len())
                .ok_or_else(invalid)?;
            let expects_tail = self.finalized && !candidate.buffer.is_empty();
            let expected_digest = expects_tail.then(|| crate::sha256(&candidate.buffer));
            if terminal.is_some()
                || candidate.buffer_start != last_message_end
                || buffer_end != self.next_offset
                || tail.is_some() != expects_tail
                || tail.is_some_and(|transition| {
                    transition.stream_range.start != candidate.buffer_start
                        || transition.stream_range.end != buffer_end
                        || transition.evidence_sha256.as_deref() != expected_digest.as_deref()
                })
            {
                return Err(invalid());
            }
        } else {
            let terminal = terminal.ok_or_else(invalid)?;
            if !candidate.buffer.is_empty()
                || terminal.stream_range.start != last_message_end
                || terminal.stream_range.end > self.next_offset
                || tail.is_some()
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    fn validate_gappy_candidate(
        &self,
        framing_index: usize,
        candidate: &CandidateState,
        last_message_end: usize,
        terminal: Option<&StreamTransition>,
        first_gap: Interval,
    ) -> Result<(), ProtocolError> {
        let invalid = || ProtocolError::InvalidParserState;
        // The first gap ends framing for every candidate
        let mut pre_gap_tails = self
            .candidate_tails(framing_index)
            .filter(|transition| transition.stream_range.end <= first_gap.0);
        let pre_gap_tail = pre_gap_tails.next();
        if pre_gap_tails.next().is_some() {
            return Err(invalid());
        }

        if candidate.active || !candidate.buffer.is_empty() {
            return Err(invalid());
        }
        if last_message_end > first_gap.0 {
            return Err(invalid());
        }
        if let Some(terminal) = terminal {
            if terminal.stream_range.start != last_message_end
                || terminal.stream_range.end > first_gap.0
                || pre_gap_tail.is_some()
            {
                return Err(invalid());
            }
        } else {
            let expects_tail = last_message_end < first_gap.0;
            if pre_gap_tail.is_some() != expects_tail
                || pre_gap_tail.is_some_and(|transition| {
                    transition.stream_range.start != last_message_end
                        || transition.stream_range.end != first_gap.0
                })
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    fn validate_post_gap_tails(&self, gaps: &[Interval]) -> Result<(), ProtocolError> {
        if gaps.is_empty() {
            return Ok(());
        }
        let invalid = || ProtocolError::InvalidParserState;
        let expected_range_count = if self.finalized {
            gaps.len()
        } else {
            gaps.len().checked_sub(1).ok_or_else(invalid)?
        };
        let expected_count = expected_range_count
            .checked_mul(self.candidates.len())
            .ok_or_else(invalid)?;
        let mut expected = Vec::new();
        expected
            .try_reserve_exact(expected_count)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        for (gap_index, gap) in gaps.iter().take(expected_range_count).enumerate() {
            let tail_end = gaps
                .get(gap_index + 1)
                .map_or(self.next_offset, |next_gap| next_gap.0);
            if gap.1 >= tail_end {
                return Err(invalid());
            }
            for framing_index in 0..self.candidates.len() {
                expected.push((framing_index, gap.1, tail_end));
            }
        }

        let first_gap = gaps.first().ok_or_else(invalid)?;
        let mut observed = Vec::new();
        let post_gap_count = self
            .transitions
            .iter()
            .filter(|transition| {
                transition.state == StreamTransitionState::UnresolvedTail
                    && transition.stream_range.end > first_gap.0
            })
            .count();
        observed
            .try_reserve_exact(post_gap_count)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        for transition in self
            .transitions
            .iter()
            .filter(|transition| transition.state == StreamTransitionState::UnresolvedTail)
        {
            let range = (transition.stream_range.start, transition.stream_range.end);
            if range.1 <= first_gap.0 {
                continue;
            }
            if range.0 < first_gap.1 {
                return Err(invalid());
            }
            observed.push((transition.framing_index, range.0, range.1));
        }
        expected.sort_unstable();
        observed.sort_unstable();
        if observed != expected {
            return Err(invalid());
        }
        Ok(())
    }
}
