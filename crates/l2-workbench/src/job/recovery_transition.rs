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
}

impl RecoveryTransitionOutcome {
    const ALL: [Self; 9] = [
        Self::Derived,
        Self::ReportRetained,
        Self::Hypothesis,
        Self::Validated,
        Self::Contradicted,
        Self::InputContradicted,
        Self::BudgetExhausted,
        Self::WorkOmitted,
        Self::Unsupported,
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
pub struct RecoveryTransitionSample {
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
                existing.sample = Some(
                    existing
                        .sample
                        .map_or(sample, |current| current.min(sample)),
                );
            }
        } else if self.records.len() < MAX_RECORDS {
            self.records.push(record);
            self.records
                .sort_unstable_by_key(|record| (record.stage, record.outcome));
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
