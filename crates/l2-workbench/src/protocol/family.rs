//! Bounded message-family selectors learned from repeated training observations

use super::observation::{
    ByteObservation, ObservationCohort, ObservationCoverage, ObservationError, ObservationInput,
    ObservationLimits, ObservationPlan, ObservationProvenance, RegionObservation, SampleRange,
    observe,
};
use super::{
    ByteRange, MAX_MESSAGE_BYTES, MAX_PROTOCOL_BYTES, MAX_PROTOCOL_SAMPLES, MessageSample,
};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::mem::size_of;

/// Maximum number of message samples admitted to one family pass
pub const DEFAULT_MAX_FAMILY_SAMPLES: usize = 64;
/// Maximum requested byte ranges considered by one family pass
pub const DEFAULT_MAX_FAMILY_RANGES: usize = 4_096;
/// Maximum selector alternatives retained from one observation pass
pub const DEFAULT_MAX_FAMILY_SELECTORS: usize = 32;
/// Maximum supported values retained for one selector
pub const DEFAULT_MAX_FAMILY_VALUES: usize = 16;
/// Maximum logical bytes retained for family metadata
pub const DEFAULT_MAX_FAMILY_REPORT_BYTES: usize = 1024 * 1024;

/// Work, byte, and report bounds for one message-family discovery pass
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageFamilyLimits {
    /// Maximum input messages inspected in caller order
    pub max_samples: usize,
    /// Maximum bytes inspected from any one message
    pub max_message_bytes: usize,
    /// Maximum aggregate input bytes inspected
    pub max_total_bytes: usize,
    /// Inclusive final byte offset considered for family selectors
    pub max_selector_offset: usize,
    /// Maximum selector width in bytes
    pub max_selector_width: usize,
    /// Distinct training sessions required to support one family value
    pub min_training_sessions_per_family: usize,
    /// Maximum sample-specific byte ranges requested from observation analysis
    pub max_candidate_ranges: usize,
    /// Maximum selector alternatives retained
    pub max_selectors: usize,
    /// Maximum family values retained for one selector
    pub max_families_per_selector: usize,
    /// Maximum analysis steps performed by observation and family grouping
    pub max_work_units: usize,
    /// Maximum logical metadata bytes retained by the report
    pub max_report_bytes: usize,
}

impl Default for MessageFamilyLimits {
    fn default() -> Self {
        Self {
            max_samples: DEFAULT_MAX_FAMILY_SAMPLES,
            max_message_bytes: MAX_MESSAGE_BYTES,
            max_total_bytes: MAX_PROTOCOL_BYTES,
            max_selector_offset: 15,
            max_selector_width: 4,
            min_training_sessions_per_family: 2,
            max_candidate_ranges: DEFAULT_MAX_FAMILY_RANGES,
            max_selectors: DEFAULT_MAX_FAMILY_SELECTORS,
            max_families_per_selector: DEFAULT_MAX_FAMILY_VALUES,
            max_work_units: 1_000_000,
            max_report_bytes: DEFAULT_MAX_FAMILY_REPORT_BYTES,
        }
    }
}

/// One supported exact selector value and its training and held-out observations
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageFamily {
    /// Exact bytes selected by this family
    pub value: Vec<u8>,
    /// Caller sample IDs supporting the value in training
    pub training_samples: Vec<u64>,
    /// Distinct session IDs supporting the value in training
    pub training_sessions: Vec<u64>,
    /// Caller sample IDs that matched this frozen value in holdout
    pub heldout_samples: Vec<u64>,
    /// Distinct session IDs that matched this frozen value in holdout
    pub heldout_sessions: Vec<u64>,
    /// Indices into the retained observation report for training provenance
    pub training_observation_indices: Vec<usize>,
    /// Indices into the retained observation report for held-out provenance
    pub heldout_observation_indices: Vec<usize>,
}

/// Why one observed message did not match a retained family value
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnassignedFamilyReason {
    /// The requested selector range was outside the message
    RangeUnavailable,
    /// The raw fact could not be retained under an observation limit
    ObservationOmitted,
    /// The training value lacked support from enough distinct sessions
    InsufficientTrainingSupport,
    /// The training value was supported but fell beyond the family retention limit
    FamilyLimit,
    /// The held-out value was absent from the frozen training selector
    UnseenValue,
}

impl UnassignedFamilyReason {
    /// Stable machine-readable reason for this unassigned observation
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RangeUnavailable => "range_unavailable",
            Self::ObservationOmitted => "observation_omitted",
            Self::InsufficientTrainingSupport => "insufficient_training_support",
            Self::FamilyLimit => "family_limit",
            Self::UnseenValue => "unseen_value",
        }
    }
}

/// Sample retained as evidence but not assigned to a supported selector value
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnassignedFamilyObservation {
    /// Caller-provided sample identifier
    pub sample: u64,
    /// Exact selected bytes, absent when the range could not be observed
    pub value: Option<Vec<u8>>,
    /// Reason the sample did not receive a family assignment
    pub reason: UnassignedFamilyReason,
    /// Index in the retained observation report, when its raw fact was retained
    pub observation_index: Option<usize>,
}

/// One bounded selector alternative scoped to a source, capture scope, and direction
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageFamilySelector {
    /// Source/scope/direction cohort used for exact value comparison
    pub cohort: ObservationCohort,
    /// Half-open selector range relative to every message in the cohort
    pub range: ByteRange,
    /// Supported exact values learned from training only
    pub families: Vec<MessageFamily>,
    /// Messages whose value was unknown, unsupported, or not observable
    pub unassigned: Vec<UnassignedFamilyObservation>,
    /// Training observations covered this complete range without omission
    pub training_coverage_complete: bool,
    /// Number of additional supported values omitted by the family cap
    pub omitted_families: usize,
}

/// Aggregate input, work, and selector coverage for one family pass
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageFamilyReport {
    /// Retained selector alternatives, ordered by byte range and cohort
    pub selectors: Vec<MessageFamilySelector>,
    /// Raw byte observations and source provenance used by the selectors
    pub observations: super::observation::ObservationReport,
    /// Input and per-region observation coverage
    pub observation_coverage: ObservationCoverage,
    /// Total supplied messages, including messages beyond `max_samples`
    pub samples_seen: usize,
    /// Number of input messages assigned to the training partition
    pub training_samples: usize,
    /// Number of input messages assigned to the held-out partition
    pub heldout_samples: usize,
    /// Requested sample/range pairs skipped by the family range cap
    pub omitted_candidate_ranges: usize,
    /// Supported selector alternatives omitted by report or selector limits
    pub omitted_selectors: usize,
    /// Logical bytes retained for selector metadata and observations
    pub report_bytes_retained: usize,
    /// True only when the supplied inputs and every considered region fit the limits
    pub complete: bool,
}

/// Invalid training partition, resource limits, or bounded allocation during family discovery
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageFamilyError {
    /// One or more required resource limits are zero or exceed supported bounds
    InvalidLimits,
    /// The training partition repeats a sample identifier
    DuplicateTrainingSample { sample: u64 },
    /// Two input messages use the same caller-supplied sample identifier
    DuplicateInputSample { sample: u64 },
    /// A training identifier is absent from the input messages
    MissingTrainingSample { sample: u64 },
    /// Supplied messages exceed the protocol sample ceiling
    TooManySamples { count: usize, maximum: usize },
    /// Observation analysis rejected its input or work limits
    Observation(ObservationError),
    /// Observation analysis returned an internally inconsistent fact index
    InvalidObservationReport,
    /// A bounded collection could not reserve its requested capacity
    AllocationFailed { field: &'static str },
}

impl Display for MessageFamilyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("message-family limits must be positive"),
            Self::DuplicateTrainingSample { sample } => {
                write!(formatter, "training sample {sample} appears more than once")
            }
            Self::DuplicateInputSample { sample } => {
                write!(formatter, "input sample {sample} appears more than once")
            }
            Self::MissingTrainingSample { sample } => {
                write!(
                    formatter,
                    "training sample {sample} is missing from the input"
                )
            }
            Self::TooManySamples { count, maximum } => {
                write!(
                    formatter,
                    "message-family input has {count} samples; maximum is {maximum}"
                )
            }
            Self::Observation(error) => write!(formatter, "message-family observation: {error}"),
            Self::InvalidObservationReport => {
                formatter.write_str("message-family observation report is inconsistent")
            }
            Self::AllocationFailed { field } => {
                write!(formatter, "could not reserve memory for {field}")
            }
        }
    }
}

impl Error for MessageFamilyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Observation(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ObservationError> for MessageFamilyError {
    fn from(error: ObservationError) -> Self {
        Self::Observation(error)
    }
}

/// Learn exact message-family selectors from repeated training observations
///
/// The selector values come only from `training_samples`. Held-out values can match
/// those frozen values, but never create a new family. A value needs support from
/// multiple training sessions within one source/scope/direction cohort
///
/// # Errors
/// Returns an error for invalid limits, missing or repeated training identifiers,
/// observation failures, or bounded allocation failures
pub fn discover_message_families(
    samples: &[MessageSample<'_>],
    training_samples: &[u64],
    limits: MessageFamilyLimits,
) -> Result<MessageFamilyReport, MessageFamilyError> {
    validate_limits(limits)?;
    if samples.len() > MAX_PROTOCOL_SAMPLES {
        return Err(MessageFamilyError::TooManySamples {
            count: samples.len(),
            maximum: MAX_PROTOCOL_SAMPLES,
        });
    }
    let training_ids = training_id_set(samples, training_samples)?;
    let admitted = admit_samples(samples, &training_ids, limits.max_samples)?;
    let observation_inputs = observation_inputs(admitted.samples.as_slice())?;
    let (region_ranges, omitted_candidate_ranges) =
        candidate_ranges(admitted.samples.as_slice(), limits)?;
    let observation_limits = observation_limits(limits, region_ranges.len());
    let observation_plan = ObservationPlan {
        region_ranges,
        limits: observation_limits,
    };
    let observations = observe(&observation_inputs, &observation_plan)?;
    finish_family_report(
        samples,
        &training_ids,
        &admitted,
        observations,
        omitted_candidate_ranges,
        limits,
    )
}

struct AdmittedSamples<'a> {
    samples: Vec<MessageSample<'a>>,
    training_count: usize,
    omitted_training: usize,
    omitted_heldout: usize,
}

fn admit_samples<'a>(
    samples: &[MessageSample<'a>],
    training_ids: &BTreeSet<u64>,
    maximum: usize,
) -> Result<AdmittedSamples<'a>, MessageFamilyError> {
    let mut admitted = Vec::new();
    admitted
        .try_reserve_exact(maximum.min(samples.len()))
        .map_err(|_| MessageFamilyError::AllocationFailed {
            field: "admitted family samples",
        })?;
    for sample in samples
        .iter()
        .filter(|sample| training_ids.contains(&sample.sample))
        .take(maximum)
    {
        admitted.push(sample.clone());
    }
    let admitted_training_count = admitted.len();
    for sample in samples
        .iter()
        .filter(|sample| !training_ids.contains(&sample.sample))
        .take(maximum.saturating_sub(admitted.len()))
    {
        admitted.push(sample.clone());
    }
    let admitted_heldout_count = admitted.len().saturating_sub(admitted_training_count);
    Ok(AdmittedSamples {
        samples: admitted,
        training_count: admitted_training_count,
        omitted_training: training_ids.len().saturating_sub(admitted_training_count),
        omitted_heldout: samples
            .len()
            .saturating_sub(training_ids.len())
            .saturating_sub(admitted_heldout_count),
    })
}

fn finish_family_report(
    samples: &[MessageSample<'_>],
    training_ids: &BTreeSet<u64>,
    admitted: &AdmittedSamples<'_>,
    observations: super::observation::ObservationReport,
    omitted_candidate_ranges: usize,
    limits: MessageFamilyLimits,
) -> Result<MessageFamilyReport, MessageFamilyError> {
    let admitted_training_count = admitted.training_count;
    let admitted_heldout_count = admitted
        .samples
        .len()
        .saturating_sub(admitted_training_count);
    let observation_coverage = observations.coverage;
    let mut selectors = selectors_from_observations(
        samples,
        admitted.samples.as_slice(),
        training_ids,
        &observations,
        limits,
        admitted.omitted_training,
    )?;
    selectors.sort_unstable_by(selector_order);

    let omitted_by_selector_limit = selectors.len().saturating_sub(limits.max_selectors);
    selectors.truncate(limits.max_selectors);
    let metadata_bytes = selectors.iter().try_fold(0_usize, |total, selector| {
        total.checked_add(selector_size(selector))
    });
    let mut complete = observations.coverage.complete && omitted_candidate_ranges == 0;
    let mut report_bytes_retained = observations.coverage.report_bytes_retained;
    let mut omitted_selectors = omitted_by_selector_limit;
    let mut retained_selectors = selectors;
    if let Some(metadata_bytes) = metadata_bytes {
        if report_bytes_retained
            .checked_add(metadata_bytes)
            .is_some_and(|total| total <= limits.max_report_bytes)
        {
            report_bytes_retained += metadata_bytes;
        } else {
            omitted_selectors = omitted_selectors.saturating_add(retained_selectors.len());
            retained_selectors.clear();
            complete = false;
        }
    } else {
        omitted_selectors = omitted_selectors.saturating_add(retained_selectors.len());
        retained_selectors.clear();
        complete = false;
    }
    if omitted_selectors > 0
        || observation_coverage.omitted_samples > 0
        || retained_selectors
            .iter()
            .any(|selector| selector.omitted_families > 0)
    {
        complete = false;
    }

    Ok(MessageFamilyReport {
        selectors: retained_selectors,
        observations,
        observation_coverage,
        samples_seen: samples.len(),
        training_samples: admitted_training_count,
        heldout_samples: admitted_heldout_count,
        omitted_candidate_ranges,
        omitted_selectors,
        report_bytes_retained,
        complete: complete && admitted.omitted_training == 0 && admitted.omitted_heldout == 0,
    })
}

const fn validate_limits(limits: MessageFamilyLimits) -> Result<(), MessageFamilyError> {
    if limits.max_samples == 0
        || limits.max_message_bytes == 0
        || limits.max_total_bytes == 0
        || limits.max_selector_width == 0
        || limits.min_training_sessions_per_family == 0
        || limits.max_candidate_ranges == 0
        || limits.max_selectors == 0
        || limits.max_families_per_selector == 0
        || limits.max_work_units == 0
        || limits.max_report_bytes < 2
        || limits.max_samples > DEFAULT_MAX_FAMILY_SAMPLES
        || limits.max_message_bytes > MAX_MESSAGE_BYTES
        || limits.max_total_bytes > MAX_PROTOCOL_BYTES
        || limits.max_selector_offset > 255
        || limits.max_selector_width > 256
        || limits.max_candidate_ranges > DEFAULT_MAX_FAMILY_RANGES
        || limits.max_selectors > DEFAULT_MAX_FAMILY_SELECTORS
        || limits.max_families_per_selector > DEFAULT_MAX_FAMILY_VALUES
        || limits.max_report_bytes > DEFAULT_MAX_FAMILY_REPORT_BYTES
    {
        return Err(MessageFamilyError::InvalidLimits);
    }
    Ok(())
}

fn training_id_set(
    samples: &[MessageSample<'_>],
    training_samples: &[u64],
) -> Result<BTreeSet<u64>, MessageFamilyError> {
    let mut input_ids = BTreeSet::new();
    for sample in samples {
        if !input_ids.insert(sample.sample) {
            return Err(MessageFamilyError::DuplicateInputSample {
                sample: sample.sample,
            });
        }
    }
    let mut ids = BTreeSet::new();
    for sample in training_samples {
        if !ids.insert(*sample) {
            return Err(MessageFamilyError::DuplicateTrainingSample { sample: *sample });
        }
        if !input_ids.contains(sample) {
            return Err(MessageFamilyError::MissingTrainingSample { sample: *sample });
        }
    }
    Ok(ids)
}

fn observation_inputs<'a>(
    samples: &'a [MessageSample<'a>],
) -> Result<Vec<ObservationInput<'a>>, MessageFamilyError> {
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(samples.len())
        .map_err(|_| MessageFamilyError::AllocationFailed {
            field: "message-family observation inputs",
        })?;
    for sample in samples {
        inputs.push(ObservationInput {
            message: sample.clone(),
            provenance: ObservationProvenance::Derived {
                identity: "message-family-input",
                range: ByteRange {
                    start: 0,
                    end: sample.bytes.len(),
                },
            },
        });
    }
    Ok(inputs)
}

fn candidate_ranges(
    samples: &[MessageSample<'_>],
    limits: MessageFamilyLimits,
) -> Result<(Vec<SampleRange>, usize), MessageFamilyError> {
    let possible_widths = limits
        .max_selector_offset
        .checked_add(1)
        .and_then(|offsets| offsets.checked_mul(limits.max_selector_width))
        .ok_or(MessageFamilyError::InvalidLimits)?;
    let possible_ranges = possible_widths
        .checked_mul(samples.len())
        .ok_or(MessageFamilyError::InvalidLimits)?;
    let complete_width_count = limits.max_candidate_ranges / samples.len().max(1);
    let retained_width_count = possible_widths.min(complete_width_count);
    let retained_ranges = retained_width_count
        .checked_mul(samples.len())
        .ok_or(MessageFamilyError::InvalidLimits)?;
    let mut ranges = Vec::new();
    ranges.try_reserve_exact(retained_ranges).map_err(|_| {
        MessageFamilyError::AllocationFailed {
            field: "family selector ranges",
        }
    })?;
    let mut candidate_index = 0_usize;
    'offsets: for offset in 0..=limits.max_selector_offset {
        for width in 1..=limits.max_selector_width {
            if candidate_index >= retained_width_count {
                break 'offsets;
            }
            let end = offset
                .checked_add(width)
                .ok_or(MessageFamilyError::InvalidLimits)?;
            for sample in samples {
                ranges.push(SampleRange {
                    sample: sample.sample,
                    range: ByteRange { start: offset, end },
                });
            }
            candidate_index = candidate_index.saturating_add(1);
        }
    }
    let omitted_ranges = possible_ranges.saturating_sub(ranges.len());
    Ok((ranges, omitted_ranges))
}

fn observation_limits(limits: MessageFamilyLimits, range_count: usize) -> ObservationLimits {
    ObservationLimits {
        max_samples: limits.max_samples,
        max_message_bytes: limits.max_message_bytes,
        max_total_bytes: limits.max_total_bytes,
        max_prefix_offset: 0,
        max_hypotheses: 64,
        max_work_units: limits.max_work_units,
        max_byte_observations: range_count.saturating_mul(5).max(1),
        max_constraints: limits.max_samples.saturating_mul(64),
        max_region_ranges: range_count.max(1),
        max_region_width: limits.max_selector_width,
        max_region_values: range_count.max(1),
        max_region_occurrences: range_count.max(1),
        max_report_bytes: limits.max_report_bytes / 2,
        ..ObservationLimits::default()
    }
}

fn selectors_from_observations(
    all_samples: &[MessageSample<'_>],
    admitted_samples: &[MessageSample<'_>],
    training_ids: &BTreeSet<u64>,
    observations: &super::observation::ObservationReport,
    limits: MessageFamilyLimits,
    omitted_training_samples: usize,
) -> Result<Vec<MessageFamilySelector>, MessageFamilyError> {
    let mut selectors = Vec::new();
    selectors
        .try_reserve(
            observations
                .regions
                .len()
                .min(limits.max_selectors.saturating_mul(4)),
        )
        .map_err(|_| MessageFamilyError::AllocationFailed {
            field: "family selectors",
        })?;
    for region in &observations.regions {
        let selector = selector_from_region(
            region,
            observations.byte_observations.as_slice(),
            all_samples,
            admitted_samples,
            training_ids,
            limits,
            omitted_training_samples,
        )?;
        if let Some(selector) = selector {
            selectors
                .try_reserve(1)
                .map_err(|_| MessageFamilyError::AllocationFailed {
                    field: "family selectors",
                })?;
            selectors.push(selector);
        }
    }
    Ok(selectors)
}

fn selector_from_region(
    region: &RegionObservation,
    byte_observations: &[ByteObservation],
    all_samples: &[MessageSample<'_>],
    admitted_samples: &[MessageSample<'_>],
    training_ids: &BTreeSet<u64>,
    limits: MessageFamilyLimits,
    omitted_training_samples: usize,
) -> Result<Option<MessageFamilySelector>, MessageFamilyError> {
    let training_cohort = training_cohort_size(all_samples, training_ids, &region.cohort);
    if training_cohort < limits.min_training_sessions_per_family {
        return Ok(None);
    }
    let (mut families, seen_training) = supported_families(
        region,
        byte_observations,
        training_ids,
        limits.min_training_sessions_per_family,
    )?;
    if families.is_empty() {
        return Ok(None);
    }
    families.sort_unstable_by(|left, right| {
        right
            .training_sessions
            .len()
            .cmp(&left.training_sessions.len())
            .then_with(|| left.value.cmp(&right.value))
    });
    let omitted_families = families
        .len()
        .saturating_sub(limits.max_families_per_selector);
    let omitted_values = families
        .iter()
        .skip(limits.max_families_per_selector)
        .map(|family| family.value.clone())
        .collect::<Vec<_>>();
    families.truncate(limits.max_families_per_selector);
    let retained_samples = observations_by_sample(region, byte_observations)?;
    let training_coverage_complete = omitted_training_samples == 0
        && seen_training.len() == training_cohort
        && region.coverage.omitted_occurrences == 0
        && region.coverage.untestable_occurrences == 0;
    if !training_coverage_complete {
        return Ok(None);
    }
    let unassigned = unassigned_observations(
        admitted_samples,
        &region.cohort,
        region.range,
        &families,
        omitted_values.as_slice(),
        &retained_samples,
        training_ids,
    );
    Ok(Some(MessageFamilySelector {
        cohort: region.cohort.clone(),
        range: region.range,
        families,
        unassigned,
        training_coverage_complete,
        omitted_families,
    }))
}

fn training_cohort_size(
    samples: &[MessageSample<'_>],
    training_ids: &BTreeSet<u64>,
    cohort: &ObservationCohort,
) -> usize {
    samples
        .iter()
        .filter(|sample| {
            training_ids.contains(&sample.sample)
                && sample
                    .context
                    .as_ref()
                    .is_some_and(|context| ObservationCohort::from(context) == *cohort)
        })
        .count()
}

fn supported_families(
    region: &RegionObservation,
    byte_observations: &[ByteObservation],
    training_ids: &BTreeSet<u64>,
    minimum_sessions: usize,
) -> Result<(Vec<MessageFamily>, BTreeSet<u64>), MessageFamilyError> {
    let mut seen_training = BTreeSet::new();
    let mut families = Vec::new();
    for value in &region.values {
        let (training, heldout) = observations_for_value(
            value.observation_indices.as_slice(),
            byte_observations,
            training_ids,
            &region.cohort,
        )?;
        add_training_samples(&training, byte_observations, &mut seen_training)?;
        if let Some(family) = message_family(
            value.bytes.as_slice(),
            training,
            heldout,
            byte_observations,
            minimum_sessions,
        )? {
            families.push(family);
        }
    }
    Ok((families, seen_training))
}

fn add_training_samples(
    indices: &[usize],
    byte_observations: &[ByteObservation],
    samples: &mut BTreeSet<u64>,
) -> Result<(), MessageFamilyError> {
    for index in indices {
        let sample = byte_observations
            .get(*index)
            .ok_or(MessageFamilyError::InvalidObservationReport)?
            .sample;
        samples.insert(sample);
    }
    Ok(())
}

fn message_family(
    value: &[u8],
    training: Vec<usize>,
    heldout: Vec<usize>,
    byte_observations: &[ByteObservation],
    minimum_sessions: usize,
) -> Result<Option<MessageFamily>, MessageFamilyError> {
    let mut training_sessions = session_ids(&training, byte_observations)?;
    if training_sessions.len() < minimum_sessions {
        return Ok(None);
    }
    training_sessions.sort_unstable();
    let mut training_samples = sample_ids(&training, byte_observations)?;
    training_samples.sort_unstable();
    let mut heldout_samples = sample_ids(&heldout, byte_observations)?;
    heldout_samples.sort_unstable();
    let mut heldout_sessions = session_ids(&heldout, byte_observations)?;
    heldout_sessions.sort_unstable();
    Ok(Some(MessageFamily {
        value: value.to_vec(),
        training_samples,
        training_sessions,
        heldout_samples,
        heldout_sessions,
        training_observation_indices: training,
        heldout_observation_indices: heldout,
    }))
}

fn observations_for_value(
    indices: &[usize],
    byte_observations: &[ByteObservation],
    training_ids: &BTreeSet<u64>,
    cohort: &ObservationCohort,
) -> Result<(Vec<usize>, Vec<usize>), MessageFamilyError> {
    let mut training = Vec::new();
    let mut heldout = Vec::new();
    for index in indices {
        let observation = byte_observations
            .get(*index)
            .ok_or(MessageFamilyError::InvalidObservationReport)?;
        if observation.context.as_ref().map(ObservationCohort::from) != Some(cohort.clone()) {
            continue;
        }
        if training_ids.contains(&observation.sample) {
            training.push(*index);
        } else {
            heldout.push(*index);
        }
    }
    Ok((training, heldout))
}

fn sample_ids(
    indices: &[usize],
    byte_observations: &[ByteObservation],
) -> Result<Vec<u64>, MessageFamilyError> {
    indices
        .iter()
        .map(|index| {
            byte_observations
                .get(*index)
                .map(|observation| observation.sample)
                .ok_or(MessageFamilyError::InvalidObservationReport)
        })
        .collect()
}

fn session_ids(
    indices: &[usize],
    byte_observations: &[ByteObservation],
) -> Result<Vec<u64>, MessageFamilyError> {
    let mut sessions = BTreeSet::new();
    for index in indices {
        let session = byte_observations
            .get(*index)
            .and_then(|observation| observation.context.as_ref())
            .map(|context| context.session)
            .ok_or(MessageFamilyError::InvalidObservationReport)?;
        sessions.insert(session);
    }
    Ok(sessions.into_iter().collect())
}

fn observations_by_sample(
    region: &RegionObservation,
    byte_observations: &[ByteObservation],
) -> Result<Vec<(u64, usize, Vec<u8>)>, MessageFamilyError> {
    let mut facts = Vec::new();
    for value in &region.values {
        for index in &value.observation_indices {
            let observation = byte_observations
                .get(*index)
                .ok_or(MessageFamilyError::InvalidObservationReport)?;
            facts.push((observation.sample, *index, value.bytes.clone()));
        }
    }
    facts.sort_unstable_by_key(|fact| fact.0);
    Ok(facts)
}

fn unassigned_observations(
    samples: &[MessageSample<'_>],
    cohort: &ObservationCohort,
    range: ByteRange,
    families: &[MessageFamily],
    omitted_values: &[Vec<u8>],
    retained_samples: &[(u64, usize, Vec<u8>)],
    training_ids: &BTreeSet<u64>,
) -> Vec<UnassignedFamilyObservation> {
    let mut unassigned = Vec::new();
    for sample in samples.iter().filter(|sample| {
        sample
            .context
            .as_ref()
            .is_some_and(|context| ObservationCohort::from(context) == *cohort)
    }) {
        let fact = retained_samples
            .iter()
            .find(|(sample_id, _, _)| *sample_id == sample.sample);
        if fact.is_some_and(|(_, _, value)| families.iter().any(|family| family.value == *value)) {
            continue;
        }
        let (value, observation_index, reason) = if let Some((_, index, value)) = fact {
            let reason = if omitted_values.iter().any(|omitted| omitted == value) {
                UnassignedFamilyReason::FamilyLimit
            } else if training_ids.contains(&sample.sample) {
                UnassignedFamilyReason::InsufficientTrainingSupport
            } else {
                UnassignedFamilyReason::UnseenValue
            };
            (Some(value.clone()), Some(*index), reason)
        } else {
            let bytes = sample.bytes.get(range.start..range.end);
            let reason = if bytes.is_some() {
                UnassignedFamilyReason::ObservationOmitted
            } else {
                UnassignedFamilyReason::RangeUnavailable
            };
            (bytes.map(<[u8]>::to_vec), None, reason)
        };
        unassigned.push(UnassignedFamilyObservation {
            sample: sample.sample,
            value,
            reason,
            observation_index,
        });
    }
    unassigned
}

fn selector_order(
    left: &MessageFamilySelector,
    right: &MessageFamilySelector,
) -> std::cmp::Ordering {
    left.cohort
        .cmp(&right.cohort)
        .then_with(|| left.range.cmp(&right.range))
}

fn selector_size(selector: &MessageFamilySelector) -> usize {
    let base = size_of::<MessageFamilySelector>()
        .saturating_add(selector.cohort.source.len())
        .saturating_add(selector.cohort.scope.len())
        .saturating_add(
            selector
                .families
                .len()
                .saturating_mul(size_of::<MessageFamily>()),
        )
        .saturating_add(
            selector
                .unassigned
                .len()
                .saturating_mul(size_of::<UnassignedFamilyObservation>()),
        );
    let base = selector.unassigned.iter().fold(base, |total, observation| {
        total.saturating_add(observation.value.as_ref().map_or(0, Vec::len))
    });
    selector.families.iter().fold(base, |total, family| {
        total.saturating_add(family.value.len()).saturating_add(
            family
                .training_samples
                .len()
                .saturating_add(family.training_sessions.len())
                .saturating_add(family.heldout_samples.len())
                .saturating_add(family.heldout_sessions.len())
                .saturating_add(family.training_observation_indices.len())
                .saturating_add(family.heldout_observation_indices.len())
                .saturating_mul(size_of::<usize>()),
        )
    })
}
