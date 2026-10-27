//! Bounded summaries of observed recovery transitions

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, IgnoredAny, SeqAccess, Visitor},
};
use std::fmt;

mod digest;

const MAX_RECORDS: usize =
    RecoveryTransitionStage::ALL.len() * RecoveryTransitionOutcome::ALL.len();

/// Pipeline stage where a recovery event was observed
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum RecoveryTransitionStage {
    /// Candidate inputs are selected for a cohort
    Cohort,
    /// Framing is proposed or materialized
    Framing,
    /// A transformation is proposed or applied
    Transform,
    /// A record schema is proposed and checked
    Schema,
    /// Records are parsed and assembled
    Assembly,
    /// A candidate artifact is structurally validated
    Validation,
    /// A validated container is expanded
    Expansion,
    /// A retained artifact is published
    Publication,
}

impl RecoveryTransitionStage {
    const ALL: [Self; 8] = [
        Self::Cohort,
        Self::Framing,
        Self::Transform,
        Self::Schema,
        Self::Assembly,
        Self::Validation,
        Self::Expansion,
        Self::Publication,
    ];
}

/// What the observed event established about the selected candidate
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum RecoveryTransitionOutcome {
    /// The stage retained a derivation, without claiming it is the intended artifact
    Derived,
    /// The stage retained a discovery report without claiming that it contains survivors
    ReportRetained,
    /// The stage retained a hypothesis that still needs independent support
    Hypothesis,
    /// A structural validator accepted the selected exact bytes
    Validated,
    /// An explicit parser or constraint contradicted the selected candidate
    Contradicted,
    /// One input contradicted a schema even if other batch inputs were usable
    InputContradicted,
    /// An explicit resource ceiling left work incomplete
    BudgetExhausted,
    /// Other execution or coverage limits left work incomplete
    WorkOmitted,
    /// This executor does not support the selected task
    Unsupported,
    /// A source-qualified cohort was admitted to discovery
    CohortAdmitted,
    /// A cohort input failed eligibility or admission
    CohortOmitted,
    /// Eligible inputs were left out of the bounded learning sample
    LearningSampleOmitted,
    /// Atomic publication committed successfully
    Published,
    /// The destination was committed but parent synchronization failed
    PublishedDurabilityUncertain,
    /// A replacement committed but its final cleanup state is uncertain
    PublishedReplacementUncertain,
    /// Publication failed before its atomic commit
    PublicationFailed,
}

impl RecoveryTransitionOutcome {
    const ALL: [Self; 16] = [
        Self::Derived,
        Self::ReportRetained,
        Self::Hypothesis,
        Self::Validated,
        Self::Contradicted,
        Self::InputContradicted,
        Self::BudgetExhausted,
        Self::WorkOmitted,
        Self::Unsupported,
        Self::CohortAdmitted,
        Self::CohortOmitted,
        Self::LearningSampleOmitted,
        Self::Published,
        Self::PublishedDurabilityUncertain,
        Self::PublishedReplacementUncertain,
        Self::PublicationFailed,
    ];
}

/// One exact source interval supporting the example input
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTransitionSourceRange {
    /// SHA-256 of the source identified in the Case
    #[serde(with = "digest")]
    pub source_sha256: [u8; 32],
    /// Packet number when the source is a capture
    pub packet: Option<u64>,
    /// Starting source byte offset
    pub offset: u64,
    /// Number of bytes in this supporting interval
    pub length: u64,
}

/// One fixed-size reference back to a candidate and its retained Case evidence
///
/// The first input is an example, not a complete list of a batch's source nodes
/// `input_batch_sha256` binds every ordered input and origin in that batch
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCandidateSample {
    /// Coordinator-local candidate index
    pub candidate_index: u64,
    /// First source or derived Case node supplied to the candidate
    pub input_node_id: u64,
    /// SHA-256 of the first exact candidate input bytes
    #[serde(with = "digest")]
    pub input_blob_sha256: [u8; 32],
    /// SHA-256 of ordered input blob identities and their ordered origin node IDs
    #[serde(with = "digest")]
    pub input_batch_sha256: [u8; 32],
    /// SHA-256 of the submitted task's JSON representation
    #[serde(with = "digest")]
    pub task_sha256: [u8; 32],
    /// One supporting source interval, when the selected input has literal provenance
    pub source_range: Option<RecoveryTransitionSourceRange>,
    /// Number of input positions in the candidate
    pub input_count: u64,
    /// Terminal receipt or evidence node, if this outcome retained one
    pub evidence_node_id: Option<u64>,
}

/// Why an input was admitted or omitted from a discovery cohort
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum RecoveryCohortReason {
    /// The source-backed cohort was admitted
    Admitted,
    /// Input provenance did not identify a source
    MissingSource,
    /// The input combined more than one source
    MixedSource,
    /// No retained bytes were available
    MissingBlob,
    /// The run metadata was invalid
    InvalidRun,
    /// The input run was empty
    EmptyRun,
    /// The frame metadata was invalid
    InvalidFrame,
    /// A conversation ancestor was missing
    MissingContext,
    /// Several conversation ancestors were possible
    AmbiguousContext,
    /// Conversation metadata was invalid
    InvalidContext,
    /// TCP generation could not be resolved
    GenerationAmbiguous,
    /// One run exceeded its byte limit
    RunTooLarge,
    /// The framing sample count was exhausted
    TooManySamples,
    /// The framing byte budget was exhausted
    TotalBytes,
    /// A materialization receipt was missing
    MissingMaterializationReceipt,
    /// More than one materialization receipt applied
    AmbiguousMaterializationReceipt,
    /// A materialization receipt did not match its input
    InvalidMaterializationReceipt,
    /// The framing receipt reported an incomplete tail
    IncompleteFraming,
    /// Framing-selection evidence was missing
    MissingFramingSelectionEvidence,
    /// More than one framing-selection parent applied
    AmbiguousFramingSelectionEvidence,
    /// Framing-selection evidence did not match
    InvalidFramingSelectionEvidence,
    /// A framing-input edge was missing
    MissingFramingInputLink,
    /// More than one framing-input edge applied
    AmbiguousFramingInputLink,
    /// Frame indices collided within one receipt
    DuplicateReceiptFrameIndex,
    /// Learning sample count prevented inclusion
    LearningPrefixMessageCountLimit,
    /// Learning byte budget prevented inclusion
    LearningPrefixAggregateByteLimit,
    /// Both learning limits prevented inclusion
    LearningPrefixMessageAndByteLimits,
    /// Another bounded coordinator resource prevented admission
    CoordinatorLimit,
    /// Cycle detection suppressed a repeated candidate
    CoordinatorCycle,
    /// A reason was not represented by this version
    Other,
}

/// Source-qualified example of a cohort decision
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCohortSample {
    /// Complete source digest when a unique source was available
    #[serde(default, with = "digest::optional")]
    pub source_sha256: Option<[u8; 32]>,
    /// One Case input node, if retained in the omitted or admitted group
    pub input_node_id: Option<u64>,
    /// Exact bytes for that input node, when available
    #[serde(default, with = "digest::optional")]
    pub input_blob_sha256: Option<[u8; 32]>,
    /// Number of inputs represented by the recorded decision
    pub input_count: u64,
    /// Coordinator-local candidate index when admission succeeded
    pub candidate_index: Option<u64>,
    /// Digest of the ordered candidate input batch when admission succeeded
    #[serde(default, with = "digest::optional")]
    pub input_batch_sha256: Option<[u8; 32]>,
    /// Digest of the submitted task when admission succeeded
    #[serde(default, with = "digest::optional")]
    pub task_sha256: Option<[u8; 32]>,
    /// Specific reason for the decision
    pub reason: RecoveryCohortReason,
}

/// One exact artifact from the staged publication set
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryArtifactSample {
    /// Digest recorded for the staged artifact under the manifest receipt rules
    #[serde(with = "digest")]
    pub sha256: [u8; 32],
    /// Exact length of the retained artifact
    pub byte_length: u64,
}

/// Origin of the source-set digest recorded at publication
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPublicationSourceBasis {
    /// No strong source-set digest was available
    #[default]
    Unavailable,
    /// The caller supplied this source identity before staging
    RequestedIdentity,
    /// The staged manifest reported this source-set digest
    StagedManifest,
}

/// Source set and one artifact selected for atomic publication
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPublicationSample {
    /// Digest reported for the source set, when available
    #[serde(default, with = "digest::optional")]
    pub source_set_sha256: Option<[u8; 32]>,
    /// Whether the source digest came from the request or staged manifest
    #[serde(default)]
    pub source_basis: RecoveryPublicationSourceBasis,
    /// One artifact included in the staged set, when available
    pub artifact: Option<RecoveryArtifactSample>,
    /// Number of artifacts in the staged set, if it was inspected
    pub artifact_count: Option<u64>,
}

/// Fixed-size example selected for one aggregated transition
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum RecoveryTransitionSample {
    /// Exact candidate and Case evidence reference
    Candidate(RecoveryCandidateSample),
    /// Source-qualified cohort admission or omission
    Cohort(RecoveryCohortSample),
    /// Source set and artifact at an atomic publication boundary
    Publication(RecoveryPublicationSample),
}

impl<'de> Deserialize<'de> for RecoveryTransitionSample {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(
            tag = "kind",
            content = "detail",
            rename_all = "snake_case",
            deny_unknown_fields
        )]
        enum TaggedSample {
            Candidate(RecoveryCandidateSample),
            Cohort(RecoveryCohortSample),
            Publication(RecoveryPublicationSample),
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum WireSample {
            Tagged(TaggedSample),
            // Version 3 wrote candidate fields directly without a discriminant
            LegacyCandidate(RecoveryCandidateSample),
        }
        Ok(match WireSample::deserialize(deserializer)? {
            WireSample::Tagged(TaggedSample::Candidate(sample))
            | WireSample::LegacyCandidate(sample) => Self::Candidate(sample),
            WireSample::Tagged(TaggedSample::Cohort(sample)) => Self::Cohort(sample),
            WireSample::Tagged(TaggedSample::Publication(sample)) => Self::Publication(sample),
        })
    }
}

/// A single observed transition before aggregation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryTransition {
    /// Stage that produced the observation
    pub stage: RecoveryTransitionStage,
    /// Interpretation of the observation
    pub outcome: RecoveryTransitionOutcome,
    /// Optional bounded Case reference for this event
    pub sample: Option<RecoveryTransitionSample>,
}

/// Count and one deterministic example for a stage and outcome
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveryTransitionRecord {
    stage: RecoveryTransitionStage,
    outcome: RecoveryTransitionOutcome,
    count: u64,
    sample: Option<RecoveryTransitionSample>,
}

impl RecoveryTransitionRecord {
    /// Returns the observed pipeline stage
    #[must_use]
    pub const fn stage(&self) -> RecoveryTransitionStage {
        self.stage
    }
    /// Returns the observed disposition
    #[must_use]
    pub const fn outcome(&self) -> RecoveryTransitionOutcome {
        self.outcome
    }
    /// Returns the number of events, saturating at the integer limit
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }
    /// Returns one bounded example, if one was available
    #[must_use]
    pub const fn sample(&self) -> Option<&RecoveryTransitionSample> {
        self.sample.as_ref()
    }
}

impl<'de> Deserialize<'de> for RecoveryTransitionRecord {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireRecord {
            stage: RecoveryTransitionStage,
            outcome: RecoveryTransitionOutcome,
            count: u64,
            sample: Option<RecoveryTransitionSample>,
        }
        let wire = WireRecord::deserialize(deserializer)?;
        if wire.count == 0 {
            return Err(de::Error::custom(
                "recovery transition count must be nonzero",
            ));
        }
        Ok(Self {
            stage: wire.stage,
            outcome: wire.outcome,
            count: wire.count,
            sample: wire.sample,
        })
    }
}

/// Constant-bounded event counts and examples for a recovery job
///
/// These are observed transitions, not an exhaustive history or proof of ground truth
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RecoveryTransitionSummary {
    records: Vec<RecoveryTransitionRecord>,
}

impl RecoveryTransitionSummary {
    /// Returns records ordered by stage and outcome
    #[must_use]
    pub fn records(&self) -> &[RecoveryTransitionRecord] {
        &self.records
    }

    pub(super) fn record(&mut self, event: RecoveryTransition) {
        self.merge_record(RecoveryTransitionRecord {
            stage: event.stage,
            outcome: event.outcome,
            count: 1,
            sample: event.sample,
        });
    }

    pub(super) fn merge(&mut self, other: Self) {
        for record in other.records {
            self.merge_record(record);
        }
    }

    fn merge_record(&mut self, record: RecoveryTransitionRecord) {
        if let Some(existing) = self
            .records
            .iter_mut()
            .find(|existing| existing.stage == record.stage && existing.outcome == record.outcome)
        {
            existing.count = existing.count.saturating_add(record.count);
            // A stable sample makes checkpoints independent of worker update order
            if let Some(sample) = record.sample {
                existing.sample = Some(existing.sample.map_or(sample, |current| {
                    match sample_quality(&sample).cmp(&sample_quality(&current)) {
                        std::cmp::Ordering::Greater => sample,
                        std::cmp::Ordering::Less => current,
                        std::cmp::Ordering::Equal => current.min(sample),
                    }
                }));
            }
        } else if self.records.len() < MAX_RECORDS {
            self.records.push(record);
            self.records
                .sort_unstable_by_key(|record| (record.stage, record.outcome));
        }
    }
}

fn sample_quality(sample: &RecoveryTransitionSample) -> u8 {
    match sample {
        RecoveryTransitionSample::Candidate(_) => 0,
        RecoveryTransitionSample::Cohort(sample) => {
            u8::from(sample.source_sha256.is_some()) * 2 + u8::from(sample.input_node_id.is_some())
        }
        RecoveryTransitionSample::Publication(sample) => {
            let source = match sample.source_basis {
                RecoveryPublicationSourceBasis::Unavailable => 0,
                RecoveryPublicationSourceBasis::RequestedIdentity => 2,
                RecoveryPublicationSourceBasis::StagedManifest => 4,
            };
            source + u8::from(sample.artifact.is_some())
        }
    }
}

impl<'de> Deserialize<'de> for RecoveryTransitionSummary {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireSummary {
            #[serde(default)]
            records: BoundedRecords,
        }
        let mut records = WireSummary::deserialize(deserializer)?.records.0;
        records.sort_unstable_by_key(|record| (record.stage, record.outcome));
        Ok(Self { records })
    }
}

#[derive(Default)]
struct BoundedRecords(Vec<RecoveryTransitionRecord>);

impl<'de> Deserialize<'de> for BoundedRecords {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RecordsVisitor;
        impl<'de> Visitor<'de> for RecordsVisitor {
            type Value = BoundedRecords;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "at most {MAX_RECORDS} unique recovery transition records"
                )
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut records = Vec::new();
                records
                    .try_reserve(sequence.size_hint().unwrap_or_default().min(MAX_RECORDS))
                    .map_err(de::Error::custom)?;
                while records.len() < MAX_RECORDS {
                    let Some(record) = sequence.next_element::<RecoveryTransitionRecord>()? else {
                        return Ok(BoundedRecords(records));
                    };
                    if records.iter().any(|existing: &RecoveryTransitionRecord| {
                        existing.stage == record.stage && existing.outcome == record.outcome
                    }) {
                        return Err(de::Error::custom("duplicate recovery transition category"));
                    }
                    records.push(record);
                }
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("too many recovery transition categories"));
                }
                Ok(BoundedRecords(records))
            }
        }
        deserializer.deserialize_seq(RecordsVisitor)
    }
}
