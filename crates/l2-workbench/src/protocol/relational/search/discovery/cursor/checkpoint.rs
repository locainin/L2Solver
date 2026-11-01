//! Bounded cursor encoding with explicit caller-owned assessment conversion

use super::{
    CURSOR_VERSION, CandidateId, LocatorCandidate, Position, RelationalCandidateOutputs,
    RelationalCursorError, RelationalFit, RelationalFitStatus, RelationalSearchCursor,
    RelationalSessionId, RelationalTransformCandidate, RelationalTransformRule,
    RelationalTransformStatus, RetainedCandidate, SearchState,
};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};
use serde_json::{Value, value::RawValue};
use sha2::{Digest, Sha256};
use std::{
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

struct RetainedSeq<'a, T> {
    candidates: &'a [RetainedCandidate<T>],
    assessments: &'a [Value],
}
impl<T> Serialize for RetainedSeq<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.candidates.len()))?;
        for (candidate, assessment) in self.candidates.iter().zip(self.assessments) {
            seq.serialize_element(&RetainedRef {
                candidate: CandidateRef::from(&candidate.candidate),
                priority: candidate.priority,
                assessment,
                outputs: &candidate.outputs,
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
    assessment: &'a Value,
    outputs: &'a Option<RelationalCandidateOutputs>,
    captured_output_bytes: usize,
    output_capture_omitted: bool,
    search_order: usize,
}

struct SearchRef<'a, T> {
    search: &'a SearchState<'static, T>,
    assessments: &'a [Value],
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
    position: &'a Position,
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
struct EnvelopeOwned {
    version: u32,
    digest: [u8; 32],
    payload: Box<RawValue>,
}

struct LimitedWriter {
    bytes: Vec<u8>,
    limit: usize,
    failed_allocation: bool,
    exceeded: bool,
}
impl LimitedWriter {
    const fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            failed_allocation: false,
            exceeded: false,
        }
    }
    const fn failure<E>(&self) -> RelationalCursorError<E> {
        if self.failed_allocation {
            RelationalCursorError::AllocationFailed
        } else if self.exceeded {
            RelationalCursorError::CheckpointTooLarge
        } else {
            RelationalCursorError::InvalidCheckpoint
        }
    }
}
impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("checkpoint byte limit"));
        }
        if self.bytes.try_reserve(bytes.len()).is_err() {
            self.failed_allocation = true;
            return Err(io::Error::other("checkpoint allocation"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<T> RelationalSearchCursor<T> {
    /// Encode a bounded checkpoint using a caller-owned assessment representation
    ///
    /// The assessment encoder must produce a compact value and must not rely on live state.
    ///
    /// # Errors
    /// Returns an error for unsupported candidate evidence, allocation, the byte limit, or the encoder
    pub fn encode_checkpoint<E, F>(
        &self,
        max_bytes: usize,
        mut encode: F,
    ) -> Result<Vec<u8>, RelationalCursorError<E>>
    where
        F: FnMut(&T) -> Result<Value, E>,
    {
        let mut assessments = Vec::new();
        assessments
            .try_reserve_exact(self.search.candidates.len())
            .map_err(|_| RelationalCursorError::AllocationFailed)?;
        for candidate in &self.search.candidates {
            assessments
                .push(encode(&candidate.assessment).map_err(RelationalCursorError::Assessment)?);
        }
        let payload = CursorRef {
            identity: self.identity,
            history_identity: self.history_identity,
            search: SearchRef {
                search: &self.search,
                assessments: &assessments,
            },
            payload_locators: &self.payload_locators,
            absolute_locators_complete: self.absolute_locators_complete,
            initial_pairs: &self.initial_pairs,
            pre_evaluated: &self.pre_evaluated,
            position: &self.position,
        };
        let mut writer = LimitedWriter::new(max_bytes);
        if serde_json::to_writer(&mut writer, &payload).is_err() {
            return Err(writer.failure());
        }
        let digest = Sha256::digest(&writer.bytes).into();
        let text = String::from_utf8(writer.bytes)
            .map_err(|_| RelationalCursorError::InvalidCheckpoint)?;
        let raw =
            RawValue::from_string(text).map_err(|_| RelationalCursorError::InvalidCheckpoint)?;
        let mut writer = LimitedWriter::new(max_bytes);
        if serde_json::to_writer(
            &mut writer,
            &EnvelopeRef {
                version: CURSOR_VERSION,
                digest,
                payload: &raw,
            },
        )
        .is_err()
        {
            return Err(writer.failure());
        }
        Ok(writer.bytes)
    }

    /// Decode a bounded checkpoint and validate every caller-owned assessment
    ///
    /// The decoder receives the retained rule and same-pass captured outputs for cross-checking.
    /// Input, plan, history, and search positions are checked again when the search is resumed.
    ///
    /// # Errors
    /// Returns an error for corrupt or unsupported data, a byte limit, allocation, or the decoder
    pub fn decode_checkpoint<E, F>(
        bytes: &[u8],
        max_bytes: usize,
        mut decode: F,
    ) -> Result<Self, RelationalCursorError<E>>
    where
        F: FnMut(
            &RelationalTransformCandidate,
            Option<&RelationalCandidateOutputs>,
            Value,
        ) -> Result<T, E>,
    {
        if bytes.len() > max_bytes {
            return Err(RelationalCursorError::CheckpointTooLarge);
        }
        let envelope: EnvelopeOwned =
            serde_json::from_slice(bytes).map_err(|_| RelationalCursorError::InvalidCheckpoint)?;
        if envelope.version != CURSOR_VERSION
            || <[u8; 32]>::from(Sha256::digest(envelope.payload.get().as_bytes()))
                != envelope.digest
        {
            return Err(RelationalCursorError::InvalidCheckpoint);
        }
        let mut saved: CursorOwned = serde_json::from_str(envelope.payload.get())
            .map_err(|_| RelationalCursorError::InvalidCheckpoint)?;
        let mut candidates = Vec::new();
        candidates
            .try_reserve_exact(saved.search.candidates.len())
            .map_err(|_| RelationalCursorError::AllocationFailed)?;
        for retained in std::mem::take(&mut saved.search.candidates) {
            let assessment = decode(
                &retained.candidate,
                retained.outputs.as_ref(),
                retained.assessment,
            )
            .map_err(RelationalCursorError::Assessment)?;
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
        let mut pre_evaluated = BTreeSet::new();
        for id in saved.pre_evaluated {
            if !pre_evaluated.insert(id) {
                return Err(RelationalCursorError::InvalidCheckpoint);
            }
        }
        Ok(Self {
            identity: saved.identity,
            history_identity: saved.history_identity,
            search: move_search!(saved.search, candidates, None),
            payload_locators: saved.payload_locators,
            absolute_locators_complete: saved.absolute_locators_complete,
            initial_pairs: saved.initial_pairs,
            pre_evaluated,
            position: saved.position,
        })
    }
}
