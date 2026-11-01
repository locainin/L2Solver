//! Bounded cursor encoding with explicit caller-owned assessment conversion

use super::{
    CURSOR_VERSION, CandidateId, LocatorCandidate, LocatorPairSchedule, PairPosition, PairStage,
    Position, RankedPairEntry, RelationalCandidateOutputs, RelationalCursorError, RelationalFit,
    RelationalFitStatus, RelationalRestoreBudget, RelationalSearchCursor, RelationalSearchSession,
    RelationalSessionId, RelationalTransformCandidate, RelationalTransformEvaluationContext,
    RelationalTransformRule, RelationalTransformStatus, RetainedCandidate, SearchState,
    history_identity, restoration_scratch_bytes, validate_cursor,
};
use crate::job::{
    Job, JobError, JsonMemoryError, MemoryBudget, MemoryClass, MemoryError, MemoryLease, admit_json,
};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};
use serde_json::{Value, value::RawValue};
use sha2::{Digest, Sha256};
use std::{
    cmp::Reverse,
    collections::BTreeSet,
    io::{self, Write},
};

#[derive(Serialize)]
struct CandidateRef<'a> {
    rule: &'a RelationalTransformRule,
    discovery: FitRef<'a>,
    heldout: FitRef<'a>,
    status: RelationalTransformStatus,
}

impl<'a> From<&'a RelationalTransformCandidate> for CandidateRef<'a> {
    fn from(candidate: &'a RelationalTransformCandidate) -> Self {
        Self {
            rule: &candidate.rule,
            discovery: FitRef(&candidate.discovery),
            heldout: FitRef(&candidate.heldout),
            status: candidate.status,
        }
    }
}

struct FitRef<'a>(&'a RelationalFit);
impl Serialize for FitRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Fit", 5)?;
        state.serialize_field("status", &self.0.status)?;
        state.serialize_field("supported_sessions", &self.0.supported_sessions)?;
        state.serialize_field("contradicted_sessions", &self.0.contradicted_sessions)?;
        state.serialize_field("unresolved_sessions", &self.0.unresolved_sessions)?;
        state.serialize_field("checks", &ChecksRef(&self.0.checks))?;
        state.end()
    }
}
struct ChecksRef<'a>(&'a [super::super::super::super::model::RelationalSessionCheck]);
impl Serialize for ChecksRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for check in self.0 {
            let falsification = check
                .falsification
                .as_ref()
                .map(FalsificationRef::try_from)
                .transpose()
                .map_err(serde::ser::Error::custom)?;
            seq.serialize_element(&CheckRef {
                session: &check.session,
                seed_sample: check.seed_sample,
                payload_samples: &check.payload_samples,
                status: check.status,
                output_length: check.output_length,
                output_sha256: &check.output_sha256,
                falsification,
            })?;
        }
        seq.end()
    }
}
#[derive(Serialize)]
struct CheckRef<'a> {
    session: &'a RelationalSessionId,
    seed_sample: Option<u64>,
    payload_samples: &'a [u64],
    status: RelationalFitStatus,
    output_length: Option<usize>,
    output_sha256: &'a Option<String>,
    falsification: Option<FalsificationRef<'a>>,
}

#[derive(Serialize)]
enum FalsificationRef<'a> {
    SeedMessageCount {
        observed: usize,
    },
    NoPayloadMessages,
    SeedRangeUnavailable,
    SeedLengthMismatch {
        expected: usize,
        observed: Option<u64>,
    },
    PayloadLengthMismatch {
        expected: usize,
        observed: Option<u64>,
    },
    EmptyPayloadRange,
    TransformFailed {
        reason: &'a str,
    },
}
impl<'a> TryFrom<&'a super::super::super::super::model::RelationalFalsification>
    for FalsificationRef<'a>
{
    type Error = &'static str;
    fn try_from(
        value: &'a super::super::super::super::model::RelationalFalsification,
    ) -> Result<Self, Self::Error> {
        use super::super::super::super::model::RelationalFalsification as F;
        Ok(match value {
            F::SeedMessageCount { observed } => Self::SeedMessageCount {
                observed: *observed,
            },
            F::NoPayloadMessages => Self::NoPayloadMessages,
            F::SeedRangeUnavailable => Self::SeedRangeUnavailable,
            F::SeedLengthMismatch { expected, observed } => Self::SeedLengthMismatch {
                expected: *expected,
                observed: *observed,
            },
            F::PayloadLengthMismatch { expected, observed } => Self::PayloadLengthMismatch {
                expected: *expected,
                observed: *observed,
            },
            F::EmptyPayloadRange => Self::EmptyPayloadRange,
            F::TransformFailed { reason } => Self::TransformFailed { reason },
            _ => return Err("unsupported parser failure in across-session cursor"),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateOwned {
    rule: RelationalTransformRule,
    discovery: FitOwned,
    heldout: FitOwned,
    status: RelationalTransformStatus,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FitOwned {
    status: RelationalFitStatus,
    supported_sessions: Vec<RelationalSessionId>,
    contradicted_sessions: Vec<RelationalSessionId>,
    unresolved_sessions: Vec<RelationalSessionId>,
    checks: Vec<CheckOwned>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckOwned {
    session: RelationalSessionId,
    seed_sample: Option<u64>,
    payload_samples: Vec<u64>,
    status: RelationalFitStatus,
    output_length: Option<usize>,
    output_sha256: Option<String>,
    falsification: Option<FalsificationOwned>,
}
#[derive(Deserialize)]
enum FalsificationOwned {
    SeedMessageCount {
        observed: usize,
    },
    NoPayloadMessages,
    SeedRangeUnavailable,
    SeedLengthMismatch {
        expected: usize,
        observed: Option<u64>,
    },
    PayloadLengthMismatch {
        expected: usize,
        observed: Option<u64>,
    },
    EmptyPayloadRange,
    TransformFailed {
        reason: String,
    },
}
impl From<FalsificationOwned> for super::super::super::super::model::RelationalFalsification {
    fn from(value: FalsificationOwned) -> Self {
        match value {
            FalsificationOwned::SeedMessageCount { observed } => {
                Self::SeedMessageCount { observed }
            }
            FalsificationOwned::NoPayloadMessages => Self::NoPayloadMessages,
            FalsificationOwned::SeedRangeUnavailable => Self::SeedRangeUnavailable,
            FalsificationOwned::SeedLengthMismatch { expected, observed } => {
                Self::SeedLengthMismatch { expected, observed }
            }
            FalsificationOwned::PayloadLengthMismatch { expected, observed } => {
                Self::PayloadLengthMismatch { expected, observed }
            }
            FalsificationOwned::EmptyPayloadRange => Self::EmptyPayloadRange,
            FalsificationOwned::TransformFailed { reason } => Self::TransformFailed { reason },
        }
    }
}
impl From<FitOwned> for RelationalFit {
    fn from(value: FitOwned) -> Self {
        Self {
            status: value.status,
            supported_sessions: value.supported_sessions,
            contradicted_sessions: value.contradicted_sessions,
            unresolved_sessions: value.unresolved_sessions,
            checks: value
                .checks
                .into_iter()
                .map(
                    |check| super::super::super::super::model::RelationalSessionCheck {
                        session: check.session,
                        seed_sample: check.seed_sample,
                        payload_samples: check.payload_samples,
                        status: check.status,
                        output_length: check.output_length,
                        output_sha256: check.output_sha256,
                        falsification: check.falsification.map(Into::into),
                    },
                )
                .collect(),
        }
    }
}

pub(in super::super) fn deserialize_candidate<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<RelationalTransformCandidate, D::Error> {
    let value = CandidateOwned::deserialize(deserializer)?;
    Ok(RelationalTransformCandidate {
        rule: value.rule,
        discovery: value.discovery.into(),
        heldout: value.heldout.into(),
        status: value.status,
    })
}

struct EncodedAssessment {
    bytes: Vec<u8>,
    _memory: MemoryLease,
}

impl Serialize for EncodedAssessment {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value: &RawValue =
            serde_json::from_slice(&self.bytes).map_err(serde::ser::Error::custom)?;
        value.serialize(serializer)
    }
}

struct RetainedSeq<'a, T> {
    candidates: &'a [RetainedCandidate<T>],
    assessments: &'a [EncodedAssessment],
}
impl<T> Serialize for RetainedSeq<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.candidates.len()))?;
        for (candidate, assessment) in self.candidates.iter().zip(self.assessments) {
            seq.serialize_element(&RetainedRef {
                candidate: CandidateRef::from(&candidate.candidate),
                priority: candidate.priority,
                assessment,
                outputs: candidate
                    .outputs
                    .as_ref()
                    .map(super::output_codec::CandidateOutputsRef::from),
                captured_output_bytes: candidate.captured_output_bytes,
                output_capture_omitted: candidate.output_capture_omitted,
                search_order: candidate.search_order,
            })?;
        }
        seq.end()
    }
}
#[derive(Serialize)]
struct RetainedRef<'a> {
    candidate: CandidateRef<'a>,
    priority: u8,
    assessment: &'a EncodedAssessment,
    outputs: Option<super::output_codec::CandidateOutputsRef<'a>>,
    captured_output_bytes: usize,
    output_capture_omitted: bool,
    search_order: usize,
}

struct SearchRef<'a, T> {
    search: &'a SearchState<'static, T>,
    assessments: &'a [EncodedAssessment],
}
impl<T> Serialize for SearchRef<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let search = self.search;
        let mut state = serializer.serialize_struct("SearchState", 21)?;
        state.serialize_field(
            "candidates",
            &RetainedSeq {
                candidates: &search.candidates,
                assessments: self.assessments,
            },
        )?;
        state.serialize_field("candidates_examined", &search.candidates_examined)?;
        state.serialize_field(
            "history_reused_rejections",
            &search.history_reused_rejections,
        )?;
        state.serialize_field("history_reused_published", &search.history_reused_published)?;
        state.serialize_field(
            "history_recording_omissions",
            &search.history_recording_omissions,
        )?;
        state.serialize_field(
            "equivalent_candidate_aliases",
            &search.equivalent_candidate_aliases,
        )?;
        state.serialize_field("omitted_candidates", &search.omitted_candidates)?;
        state.serialize_field("omitted_candidates_exact", &search.omitted_candidates_exact)?;
        state.serialize_field("work_bytes", &search.work_bytes)?;
        state.serialize_field("search_exhaustive", &search.search_exhaustive)?;
        state.serialize_field("search_limit", &search.search_limit)?;
        state.serialize_field("search_limits", &search.search_limits)?;
        state.serialize_field(
            "locator_candidates_examined",
            &search.locator_candidates_examined,
        )?;
        state.serialize_field(
            "prefix_probe_hypotheses_examined",
            &search.prefix_probe_hypotheses_examined,
        )?;
        state.serialize_field("prefix_probes_examined", &search.prefix_probes_examined)?;
        state.serialize_field(
            "prefix_probe_cache_reuses",
            &search.prefix_probe_cache_reuses,
        )?;
        state.serialize_field(
            "prefix_probe_candidates_with_novelty",
            &search.prefix_probe_candidates_with_novelty,
        )?;
        state.serialize_field("prefix_probe_work_bytes", &search.prefix_probe_work_bytes)?;
        state.serialize_field("prefix_probe_complete", &search.prefix_probe_complete)?;
        state.serialize_field("output_bytes_retained", &search.output_bytes_retained)?;
        state.serialize_field("output_capture_omissions", &search.output_capture_omissions)?;
        state.end()
    }
}

#[derive(Serialize)]
#[serde(bound(serialize = ""))]
struct CursorRef<'a, T> {
    identity: [u8; 32],
    history_identity: Option<[u8; 32]>,
    search: SearchRef<'a, T>,
    payload_locators: &'a [LocatorCandidate],
    absolute_locators_complete: bool,
    initial_pairs: &'a [(usize, usize)],
    pre_evaluated: &'a BTreeSet<CandidateId>,
    position: PositionRef<'a>,
}

#[derive(Serialize)]
struct PositionRef<'a> {
    stage: PairStageRef<'a>,
    current: &'a Option<PairPosition>,
}

#[derive(Serialize)]
#[serde(tag = "stage", rename_all = "snake_case")]
enum PairStageRef<'a> {
    Initial { next: usize },
    Absolute { schedule: SavedScheduleRef<'a> },
    Anchored { next: usize },
}

#[derive(Serialize)]
struct SavedScheduleRef<'a> {
    initial_pair_cursor: usize,
    stream_cursor: usize,
    pairs_returned: usize,
    header: &'a [Reverse<RankedPairEntry>],
    aligned: &'a [Reverse<RankedPairEntry>],
    fallback: &'a [Reverse<RankedPairEntry>],
}

impl<'a> From<&'a LocatorPairSchedule> for SavedScheduleRef<'a> {
    fn from(schedule: &'a LocatorPairSchedule) -> Self {
        Self {
            initial_pair_cursor: schedule.initial_pair_cursor,
            stream_cursor: schedule.stream_cursor,
            pairs_returned: schedule.pairs_returned,
            header: schedule.header_aligned.pending.as_slice(),
            aligned: schedule.aligned.pending.as_slice(),
            fallback: schedule.fallback.pending.as_slice(),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorOwned {
    identity: [u8; 32],
    history_identity: Option<[u8; 32]>,
    search: SearchState<'static, Value>,
    payload_locators: Vec<LocatorCandidate>,
    absolute_locators_complete: bool,
    initial_pairs: Vec<(usize, usize)>,
    pre_evaluated: Vec<CandidateId>,
    position: Position,
}
#[derive(Serialize)]
struct EnvelopeRef<'a> {
    version: u32,
    digest: [u8; 32],
    payload: &'a RawValue,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeOwned<'a> {
    version: u32,
    digest: [u8; 32],
    #[serde(borrow)]
    payload: &'a RawValue,
}

struct LimitedWriter<'a> {
    bytes: Vec<u8>,
    limit: usize,
    memory: MemoryLease,
    failed_allocation: bool,
    exceeded: bool,
    memory_error: Option<MemoryError>,
    job: Option<&'a Job>,
    next_cancel_check: usize,
    cancelled: bool,
}
impl<'a> LimitedWriter<'a> {
    fn new(limit: usize, memory: &MemoryBudget, job: Option<&'a Job>) -> Result<Self, MemoryError> {
        Ok(Self {
            bytes: Vec::new(),
            limit,
            memory: memory.try_reserve(MemoryClass::Executor, 0)?,
            failed_allocation: false,
            exceeded: false,
            memory_error: None,
            job,
            next_cancel_check: 0,
            cancelled: false,
        })
    }
    fn failure<E>(&self) -> RelationalCursorError<E> {
        if self.cancelled {
            RelationalCursorError::Search(JobError::Cancelled.into())
        } else if let Some(error) = self.memory_error {
            RelationalCursorError::Memory(JsonMemoryError::Memory(error))
        } else if self.failed_allocation {
            RelationalCursorError::AllocationFailed
        } else if self.exceeded {
            RelationalCursorError::CheckpointTooLarge
        } else {
            RelationalCursorError::InvalidCheckpoint
        }
    }
}
impl Write for LimitedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len() >= self.next_cancel_check || bytes.len() >= 64 * 1024 {
            self.next_cancel_check = self.bytes.len().saturating_add(64 * 1024);
            if self.job.is_some_and(Job::is_cancelled) {
                self.cancelled = true;
                return Err(io::Error::other("checkpoint encoding cancelled"));
            }
        }
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("checkpoint byte limit"));
        }
        let needed = self.bytes.len() + bytes.len();
        if needed > self.bytes.capacity() {
            let old_capacity = self.bytes.capacity();
            let target = old_capacity
                .checked_mul(2)
                .unwrap_or(self.limit)
                .max(needed)
                .min(self.limit);
            // Admit old and replacement buffers together while the allocator grows the Vec
            let peak = old_capacity
                .checked_add(target)
                .and_then(|size| u64::try_from(size).ok())
                .ok_or_else(|| io::Error::other("checkpoint capacity overflow"))?;
            if let Err(error) = self.memory.try_resize(peak) {
                self.memory_error = Some(error);
                return Err(io::Error::other("checkpoint memory admission"));
            }
            if self
                .bytes
                .try_reserve_exact(target.saturating_sub(self.bytes.len()))
                .is_err()
            {
                self.failed_allocation = true;
                return Err(io::Error::other("checkpoint allocation"));
            }
            let actual = u64::try_from(self.bytes.capacity())
                .map_err(|_| io::Error::other("checkpoint capacity overflow"))?;
            if let Err(error) = self.memory.try_resize(actual) {
                self.memory_error = Some(error);
                return Err(io::Error::other("checkpoint memory admission"));
            }
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

const fn memory_failure<E>(error: MemoryError) -> RelationalCursorError<E> {
    RelationalCursorError::Memory(JsonMemoryError::Memory(error))
}

pub(super) fn reserve<E>(
    memory: &MemoryBudget,
    bytes: u64,
) -> Result<MemoryLease, RelationalCursorError<E>> {
    memory
        .try_reserve(MemoryClass::Executor, bytes)
        .map_err(memory_failure)
}

pub(super) fn check_job<E>(job: Option<&Job>) -> Result<(), RelationalCursorError<E>> {
    if let Some(job) = job {
        job.check_cancelled()
            .map_err(|error| RelationalCursorError::Search(error.into()))?;
    }
    Ok(())
}

fn admit_parse_scratch<E>(
    memory: &mut MemoryLease,
    bytes: usize,
) -> Result<(), RelationalCursorError<E>> {
    let required = u64::try_from(bytes)
        .ok()
        .and_then(|bytes| bytes.checked_mul(3))
        .ok_or(RelationalCursorError::CheckpointTooLarge)?;
    memory
        .try_resize(memory.bytes().max(required))
        .map_err(memory_failure)
}

impl RelationalSearchSession<'_, '_> {
    /// Encode a bounded cursor and the exact active history identity
    ///
    /// The encoder writes one JSON value to a bounded writer without cloning the assessment.
    /// The cursor must have been returned by this session at a completed-candidate boundary.
    /// Keep the returned lease until the encoded bytes are no longer retained.
    ///
    /// # Errors
    /// Returns an error for an incompatible cursor, allocation, byte limit, or encoder failure
    #[expect(
        clippy::too_many_lines,
        reason = "keep admitted checkpoint buffers in one encoding transaction"
    )]
    pub fn encode_checkpoint<T, E, F>(
        &self,
        cursor: &RelationalSearchCursor<T>,
        max_bytes: usize,
        memory: &MemoryBudget,
        mut encode: F,
    ) -> Result<(Vec<u8>, MemoryLease), RelationalCursorError<E>>
    where
        F: FnMut(&T, &mut dyn Write) -> Result<(), E>,
    {
        if self.complete || cursor.session_id != self.session_id || cursor.identity != self.identity
        {
            return Err(RelationalCursorError::InvalidCheckpoint);
        }
        check_job(self.job)?;
        let history_bytes = match self.history.as_deref() {
            Some(history) => history
                .checkpoint_scratch_bytes()
                .ok_or(RelationalCursorError::CheckpointTooLarge)?,
            None => 0,
        };
        let history_memory = reserve(memory, history_bytes)?;
        let history_identity = history_identity(self.history.as_deref(), self.job)
            .map_err(RelationalCursorError::Search)?;
        drop(history_memory);
        let assessment_slots = cursor
            .search
            .candidates
            .len()
            .checked_mul(2 * size_of::<EncodedAssessment>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(RelationalCursorError::CheckpointTooLarge)?;
        let _assessment_slots = reserve(memory, assessment_slots)?;
        let mut parse_memory = reserve(memory, 0)?;
        let mut assessments = Vec::new();
        assessments
            .try_reserve_exact(cursor.search.candidates.len())
            .map_err(|_| RelationalCursorError::AllocationFailed)?;
        let mut assessment_bytes = 0_usize;
        for candidate in &cursor.search.candidates {
            check_job(self.job)?;
            // The combined assessment stream cannot grow beyond the checkpoint ceiling
            let mut writer =
                LimitedWriter::new(max_bytes.saturating_sub(assessment_bytes), memory, self.job)
                    .map_err(memory_failure)?;
            let result = encode(&candidate.assessment, &mut writer);
            if writer.cancelled
                || writer.failed_allocation
                || writer.exceeded
                || writer.memory_error.is_some()
            {
                return Err(writer.failure());
            }
            check_job(self.job)?;
            result.map_err(RelationalCursorError::Assessment)?;
            assessment_bytes = assessment_bytes
                .checked_add(writer.bytes.len())
                .ok_or(RelationalCursorError::CheckpointTooLarge)?;
            admit_parse_scratch(&mut parse_memory, writer.bytes.len())?;
            let _: &RawValue = serde_json::from_slice(&writer.bytes)
                .map_err(|_| RelationalCursorError::InvalidCheckpoint)?;
            assessments.push(EncodedAssessment {
                bytes: writer.bytes,
                _memory: writer.memory,
            });
        }
        let stage = match &cursor.position.stage {
            PairStage::Initial { next } if cursor.schedule.is_none() => {
                PairStageRef::Initial { next: *next }
            }
            PairStage::Absolute { schedule: None } => PairStageRef::Absolute {
                schedule: cursor
                    .schedule
                    .as_ref()
                    .ok_or(RelationalCursorError::InvalidCheckpoint)?
                    .into(),
            },
            PairStage::Anchored { next } if cursor.schedule.is_none() => {
                PairStageRef::Anchored { next: *next }
            }
            _ => return Err(RelationalCursorError::InvalidCheckpoint),
        };
        let payload = CursorRef {
            identity: self.identity,
            history_identity,
            search: SearchRef {
                search: &cursor.search,
                assessments: &assessments,
            },
            payload_locators: &cursor.prepared.payload_locators,
            absolute_locators_complete: cursor.prepared.absolute_locators_complete,
            initial_pairs: &cursor.initial_pairs,
            pre_evaluated: &cursor.pre_evaluated,
            position: PositionRef {
                stage,
                current: &cursor.position.current,
            },
        };
        let mut writer = LimitedWriter::new(max_bytes, memory, self.job).map_err(memory_failure)?;
        if serde_json::to_writer(&mut writer, &payload).is_err() {
            return Err(writer.failure());
        }
        let digest = Sha256::digest(&writer.bytes).into();
        admit_parse_scratch(&mut parse_memory, writer.bytes.len())?;
        let raw: &RawValue = serde_json::from_slice(&writer.bytes)
            .map_err(|_| RelationalCursorError::InvalidCheckpoint)?;
        let mut output = LimitedWriter::new(max_bytes, memory, self.job).map_err(memory_failure)?;
        if serde_json::to_writer(
            &mut output,
            &EnvelopeRef {
                version: CURSOR_VERSION,
                digest,
                payload: raw,
            },
        )
        .is_err()
        {
            return Err(output.failure());
        }
        check_job(self.job)?;
        Ok((output.bytes, output.memory))
    }

    /// Admit and restore a checkpoint before converting caller-owned assessments
    ///
    /// The history must come from the same committed generation as the cursor. Cohort identity,
    /// plan, history, search positions, and captured output provenance are checked before the
    /// callback can inspect a candidate. The returned lease must remain live until the restored
    /// cursor and its retained results have been consumed. Caller-specific assessment allocations
    /// need separate admission because their representation is controlled by the callback.
    /// The executor must only restore checkpoints, history, and gate state from its own trusted
    /// committed generation. A checksum and structural validation cannot prove that claimed
    /// previous candidate evaluations were actually performed. Captured output bytes are checked
    /// against the rule and source independently before they reach the caller's decoder
    /// Restore work is charged to `work`, separate from the frozen search counters, including
    /// failed or cancelled attempts. JSON parsing is bounded by `max_bytes` and checked for
    /// cancellation immediately before and after each parse
    /// The decoder receives the same work meter and can return `RestoreWorkLimit` if its own
    /// evidence validation cannot fit in the remaining allowance
    /// Its context borrows the validated session partition and reports remaining search work at
    /// the checkpoint boundary, not the work remaining during the original candidate evaluation
    ///
    /// # Errors
    /// Returns an error for incompatible data, denied memory, cancellation, or decoder failure
    #[expect(
        clippy::too_many_lines,
        reason = "keep validation and rollback in one restoration transaction"
    )]
    pub fn restore_checkpoint<T, E, F>(
        &mut self,
        bytes: &[u8],
        max_bytes: usize,
        memory: &MemoryBudget,
        work: &mut RelationalRestoreBudget,
        mut decode: F,
    ) -> Result<(RelationalSearchCursor<T>, MemoryLease), RelationalCursorError<E>>
    where
        F: FnMut(
            &RelationalTransformEvaluationContext<'_>,
            &RelationalTransformCandidate,
            Option<&RelationalCandidateOutputs>,
            Value,
            &mut RelationalRestoreBudget,
        ) -> Result<T, RelationalCursorError<E>>,
    {
        if bytes.len() > max_bytes {
            return Err(RelationalCursorError::CheckpointTooLarge);
        }
        // A restore starts a fresh session so no other live cursor can share this history
        if self.complete || self.prepared.is_none() {
            return Err(RelationalCursorError::InvalidCheckpoint);
        }
        check_job(self.job)?;
        // Admit escaped-string scratch and retained bytes before the Base64 decoder runs
        let admission =
            admit_json(bytes, memory, MemoryClass::Executor).map_err(|error| match error {
                JsonMemoryError::InvalidJson { .. } => RelationalCursorError::InvalidCheckpoint,
                JsonMemoryError::SizeOverflow => RelationalCursorError::CheckpointTooLarge,
                JsonMemoryError::Memory(error) => {
                    RelationalCursorError::Memory(JsonMemoryError::Memory(error))
                }
            })?;
        check_job(self.job)?;
        let envelope: EnvelopeOwned<'_> =
            serde_json::from_slice(bytes).map_err(|_| RelationalCursorError::InvalidCheckpoint)?;
        check_job(self.job)?;
        if envelope.version != CURSOR_VERSION
            || <[u8; 32]>::from(Sha256::digest(envelope.payload.get().as_bytes()))
                != envelope.digest
        {
            return Err(RelationalCursorError::InvalidCheckpoint);
        }
        let mut saved: CursorOwned = serde_json::from_str(envelope.payload.get())
            .map_err(|_| RelationalCursorError::InvalidCheckpoint)?;
        check_job(self.job)?;
        if saved.identity != self.identity {
            return Err(RelationalCursorError::InvalidCheckpoint);
        }
        let history_bytes = match self.history.as_deref() {
            Some(history) => history
                .checkpoint_scratch_bytes()
                .ok_or(RelationalCursorError::CheckpointTooLarge)?,
            None => 0,
        };
        let history_memory = reserve(memory, history_bytes)?;
        let identity = history_identity(self.history.as_deref(), self.job)
            .map_err(RelationalCursorError::Search)?;
        drop(history_memory);
        if saved.history_identity != identity {
            return Err(RelationalCursorError::InvalidCheckpoint);
        }
        if saved.payload_locators.len() > self.plan.limits.max_locator_candidates
            || saved.search.candidates.len() > self.plan.limits.max_retained_candidates
            || saved.pre_evaluated.len()
                > self
                    .plan
                    .limits
                    .max_candidates
                    .saturating_add(super::INITIAL_RANK_ORDERED_PAIR_WINDOW)
        {
            return Err(RelationalCursorError::InvalidCheckpoint);
        }
        let base = self
            .prepared
            .as_ref()
            .ok_or(RelationalCursorError::InvalidCheckpoint)?;
        let validation_bytes = restoration_scratch_bytes(
            base,
            &saved.payload_locators,
            &saved.search,
            &saved.position,
            saved.pre_evaluated.len(),
        )
        .map_err(RelationalCursorError::Search)?;
        let _validation_memory = reserve(memory, validation_bytes)?;
        let mut pre_evaluated = BTreeSet::new();
        for (index, id) in saved.pre_evaluated.into_iter().enumerate() {
            if index.is_multiple_of(256) {
                check_job(self.job)?;
            }
            if !pre_evaluated.insert(id) {
                return Err(RelationalCursorError::InvalidCheckpoint);
            }
        }
        let mut prepared = self
            .prepared
            .take()
            .ok_or(RelationalCursorError::InvalidCheckpoint)?;
        let original_payloads =
            std::mem::replace(&mut prepared.payload_locators, saved.payload_locators);
        let original_complete = std::mem::replace(
            &mut prepared.absolute_locators_complete,
            saved.absolute_locators_complete,
        );
        let validation = (|| {
            validate_cursor(
                self.samples,
                &saved.search,
                &prepared,
                &saved.initial_pairs,
                &pre_evaluated,
                &saved.position,
                self.plan,
                self.options,
                self.job,
            )
            .map_err(RelationalCursorError::Search)?;
            let schedule = if let PairStage::Absolute { schedule } = &mut saved.position.stage {
                let saved_schedule = schedule
                    .take()
                    .ok_or(RelationalCursorError::InvalidCheckpoint)?;
                Some(saved_schedule.restore(
                    &prepared.seed_locators,
                    &prepared.payload_locators,
                    saved.position.current.as_ref(),
                    self.job,
                    work,
                )?)
            } else {
                None
            };
            super::output::verify_retained_outputs(
                self.samples,
                &prepared,
                &saved.search,
                self.plan,
                self.job,
                work,
            )?;
            check_job(self.job)?;
            Ok(schedule)
        })();
        let schedule = match validation {
            Ok(schedule) => schedule,
            Err(error) => {
                prepared.payload_locators = original_payloads;
                prepared.absolute_locators_complete = original_complete;
                self.prepared = Some(prepared);
                return Err(error);
            }
        };
        let mut candidates = Vec::new();
        if candidates
            .try_reserve_exact(saved.search.candidates.len())
            .is_err()
        {
            prepared.payload_locators = original_payloads;
            prepared.absolute_locators_complete = original_complete;
            self.prepared = Some(prepared);
            return Err(RelationalCursorError::AllocationFailed);
        }
        // All library-owned source ranges and digests have passed before this bridge runs
        for retained in std::mem::take(&mut saved.search.candidates) {
            if let Err(error) = check_job(self.job) {
                prepared.payload_locators = original_payloads;
                prepared.absolute_locators_complete = original_complete;
                self.prepared = Some(prepared);
                return Err(error);
            }
            let context = RelationalTransformEvaluationContext {
                discovery_sessions: &prepared.discovery_sessions,
                heldout_sessions: &prepared.heldout_sessions,
                work_bytes_remaining: self.plan.limits.max_work_bytes - saved.search.work_bytes,
            };
            let decoded = decode(
                &context,
                &retained.candidate,
                retained.outputs.as_ref(),
                retained.assessment,
                work,
            );
            if let Err(error) = check_job(self.job) {
                prepared.payload_locators = original_payloads;
                prepared.absolute_locators_complete = original_complete;
                self.prepared = Some(prepared);
                return Err(error);
            }
            let assessment = match decoded {
                Ok(assessment) => assessment,
                Err(error) => {
                    prepared.payload_locators = original_payloads;
                    prepared.absolute_locators_complete = original_complete;
                    self.prepared = Some(prepared);
                    return Err(error);
                }
            };
            candidates.push(RetainedCandidate {
                candidate: retained.candidate,
                priority: retained.priority,
                assessment,
                outputs: retained.outputs,
                captured_output_bytes: retained.captured_output_bytes,
                output_capture_omitted: retained.output_capture_omitted,
                search_order: retained.search_order,
            });
        }
        let cursor = RelationalSearchCursor {
            identity: self.identity,
            session_id: self.session_id,
            search: move_search!(saved.search, candidates, None),
            prepared,
            schedule,
            initial_pairs: saved.initial_pairs,
            pre_evaluated,
            position: saved.position,
        };
        Ok((cursor, admission.into_retained()))
    }
}
