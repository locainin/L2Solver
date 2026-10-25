use crate::derivation::{Constraint, ConstraintReport, DerivationError, Recipe, StepReport};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

/// Only selected transformation families are enumerated
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Family {
    Hex,
    Base64,
    Gzip,
    Zlib,
    Reverse,
    SingleByteXor,
    ByteAdd,
    RotateBits,
    KnownPlaintextXor {
        offset: usize,
        bytes: Vec<u8>,
        key_lengths: Vec<u16>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchPlan {
    pub families: Vec<Family>,
    pub constraints: Vec<Constraint>,
    pub max_depth: usize,
    pub max_candidates: usize,
}

/// Operational budgets shared by every canonical recipe run in one search
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchLimits {
    /// Maximum input bytes accepted by the search and its decoder runs
    pub max_input_bytes: usize,
    /// Maximum result bytes produced by one canonical transform
    pub max_output_bytes: usize,
    /// Maximum cumulative intermediate bytes in one recipe
    pub max_intermediate_bytes: usize,
    /// Maximum cumulative bytes charged to attempted search transformations
    pub max_work_bytes: usize,
    /// Maximum known-plaintext consistency tests retained
    pub max_key_tests: usize,
    /// Maximum caller-supplied variable recipe parameter bytes
    pub max_recipe_parameter_bytes: usize,
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: super::MAX_INPUT_BYTES,
            max_output_bytes: crate::derivation::MAX_OUTPUT_BYTES,
            max_intermediate_bytes: crate::derivation::MAX_INTERMEDIATE_BYTES,
            max_work_bytes: super::MAX_WORK_BYTES,
            max_key_tests: 4_096,
            max_recipe_parameter_bytes: crate::derivation::MAX_RECIPE_PARAMETER_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    ConstraintsSatisfied,
    ConstraintFailed,
    OperationFailed,
}

#[derive(Debug, Serialize)]
pub struct Candidate {
    pub id: usize,
    pub parent: Option<usize>,
    pub recipe: Recipe,
    pub status: CandidateStatus,
    pub output_length: usize,
    pub output_sha256: String,
    pub steps: Vec<StepReport>,
    pub constraints: Vec<ConstraintReport>,
    pub duplicate_of: Option<usize>,
}

/// A key period is inferred from one period and checked against remaining supplied bytes
#[derive(Debug, Serialize)]
pub struct KeyTest {
    pub parent_candidate: usize,
    pub offset: usize,
    pub key_length: usize,
    pub inferred_key: Vec<u8>,
    pub inference_bytes: usize,
    pub holdout_bytes: usize,
    pub status: KeyTestStatus,
    pub first_mismatch: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyTestStatus {
    Consistent,
    Contradicted,
    Untestable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchLimit {
    CandidateCount,
    WorkBytes,
    ExpansionBytes,
    KeyTests,
    KnownPlaintextUnavailable,
}

#[derive(Debug, Serialize)]
pub struct SearchReport {
    pub input_length: usize,
    pub input_sha256: String,
    pub plan: SearchPlan,
    /// Exact runtime budgets used for this search
    pub resources: SearchLimits,
    pub candidates: Vec<Candidate>,
    pub key_tests: Vec<KeyTest>,
    pub work_bytes: usize,
    pub search_exhaustive_within_plan: bool,
    pub limits: Vec<SearchLimit>,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug)]
pub enum SearchError {
    Invalid(&'static str),
    AllocationFailed,
    Derivation(DerivationError),
}

impl fmt::Display for SearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::AllocationFailed => {
                formatter.write_str("search could not allocate retained input")
            }
            Self::Derivation(error) => error.fmt(formatter),
        }
    }
}
impl Error for SearchError {}
impl From<DerivationError> for SearchError {
    fn from(error: DerivationError) -> Self {
        Self::Derivation(error)
    }
}
