use super::{MAX_MEASURED_BYTES, MAX_SAMPLE_BYTES, MAX_SAMPLES, MeasurementError};
use crate::evidence::EvidenceStatus;
use crate::integer::decode_unsigned;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Maximum counterexample examples retained for one tested layout
pub const MAX_LAYOUT_COUNTEREXAMPLES: usize = 32;
/// Maximum byte width tested for an explicit constant prefix
pub const MAX_PREFIX_BYTES: usize = 16;
const LENGTH_FIELD_OFFSETS: usize = 16;
const MIN_LAYOUT_SAMPLES: usize = 4;
const LAYOUT_LIMITATION: &str = "Candidate matches cover only supplied discovery and holdout samples; they do not establish a protocol grammar";
const SAMPLE_DEPENDENCE: &str = "Discovery and holdout partitions may contain retransmissions or repeated application data; sample counts do not establish independent evidence";

/// One caller-labeled message sample, in the caller's supplied packet order
#[derive(Clone, Copy, Debug)]
pub struct MessageSample<'a> {
    /// One-based sample or packet identifier retained in reports
    pub sample: u64,
    /// Exact message bytes selected by the caller
    pub bytes: &'a [u8],
}

impl<'a> MessageSample<'a> {
    /// Associate exact bytes with a stable nonzero sample identifier
    #[must_use]
    pub const fn new(sample: u64, bytes: &'a [u8]) -> Self {
        Self { sample, bytes }
    }
}

/// Byte ordering tested for an explicit length field
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteOrder {
    /// Most significant byte comes first
    BigEndian,
    /// Least significant byte comes first
    LittleEndian,
}

/// Meaning tested for a decoded length field
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LengthMeaning {
    /// The field equals the complete message length
    WholeMessage,
    /// The field equals the bytes following the end of the field
    BytesAfterField,
}

/// One explicit byte position, width, byte order, and length interpretation
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct LengthFieldCandidate {
    /// Zero-based byte offset in each message
    pub offset: usize,
    /// Width in bytes, limited to one, two, or four
    pub width: usize,
    /// Explicit candidate byte order
    pub byte_order: ByteOrder,
    /// Explicit field-to-message length relationship
    pub meaning: LengthMeaning,
}

impl LengthFieldCandidate {
    /// Generate the canonical bounded candidates in report order
    pub(crate) fn all_candidates() -> Vec<Self> {
        let mut candidates = Vec::with_capacity(LENGTH_FIELD_OFFSETS * (2 + 4 + 4));
        for offset in 0..LENGTH_FIELD_OFFSETS {
            for width in [1_usize, 2, 4] {
                let byte_orders = if width == 1 {
                    &[ByteOrder::BigEndian][..]
                } else {
                    &[ByteOrder::BigEndian, ByteOrder::LittleEndian][..]
                };
                for byte_order in byte_orders {
                    for meaning in [LengthMeaning::WholeMessage, LengthMeaning::BytesAfterField] {
                        candidates.push(Self {
                            offset,
                            width,
                            byte_order: *byte_order,
                            meaning,
                        });
                    }
                }
            }
        }
        candidates
    }

    /// Read a bounded candidate field and return its expected and observed values
    pub(crate) fn values(self, bytes: &[u8]) -> Option<(usize, u64)> {
        let field_end = self.offset.checked_add(self.width)?;
        let field = bytes.get(self.offset..field_end)?;
        let expected = match self.meaning {
            LengthMeaning::WholeMessage => bytes.len(),
            LengthMeaning::BytesAfterField => bytes.len().checked_sub(field_end)?,
        };
        let observed = decode_unsigned(field, self.byte_order == ByteOrder::LittleEndian)?;
        Some((expected, observed))
    }
}

/// One bounded field-value mismatch retained for review
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PredictionCounterexample {
    /// Caller-supplied one-based sample identifier
    pub sample: u64,
    /// Decoded field value in the candidate byte order
    pub observed: u64,
    /// Message length predicted by the candidate interpretation
    pub expected: u64,
}

/// Exact tested, matching, conflicting, and untestable sample counts
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FitSummary {
    /// Number of supplied samples in this split
    pub sample_count: usize,
    /// Samples with enough bytes to test the candidate
    pub compared: usize,
    /// Samples whose field matches the stated relationship
    pub supported: usize,
    /// Samples that contradict the stated relationship
    pub counterexample_count: usize,
    /// Samples too short to test the candidate field
    pub untestable_samples: usize,
    /// Bounded examples of counterexamples
    pub counterexamples: Vec<PredictionCounterexample>,
    /// Whether tested samples satisfy or contradict this candidate
    pub status: EvidenceStatus,
}

/// One candidate evaluated separately on discovery and held-out samples
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LengthFieldResult {
    /// Explicit field interpretation under test
    pub candidate: LengthFieldCandidate,
    /// Fit counts for the first half of supplied samples
    pub discovery: FitSummary,
    /// Fit counts for the second half of supplied samples
    pub holdout: FitSummary,
}

/// Results for the bounded candidate set and its stable split
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LengthFieldReport {
    /// All explicit candidates at offsets 0 through 15 and widths 1, 2, or 4
    pub candidates: Vec<LengthFieldResult>,
    /// One-based identifiers used for candidate discovery
    pub discovery_samples: Vec<u64>,
    /// One-based identifiers held out from candidate discovery
    pub holdout_samples: Vec<u64>,
    /// Limits on interpreting these candidate results
    pub limitations: Vec<&'static str>,
}

/// First byte that differs from an explicit constant-prefix candidate
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PrefixMismatch {
    /// Caller-supplied one-based sample identifier
    pub sample: u64,
    /// Zero-based mismatch position within the requested prefix
    pub offset: usize,
    /// Byte from the discovery reference prefix
    pub expected: u8,
    /// Byte from the candidate sample prefix
    pub observed: u8,
}

/// Bounded counts and counterexamples for one constant-prefix sample split
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PrefixFitSummary {
    /// Number of samples in this split
    pub sample_count: usize,
    /// Samples long enough to compare
    pub compared: usize,
    /// Samples with the same prefix as the discovery reference
    pub supported: usize,
    /// Samples with a prefix mismatch
    pub counterexample_count: usize,
    /// Samples shorter than the requested prefix
    pub untestable_samples: usize,
    /// Bounded examples of prefix mismatches
    pub counterexamples: Vec<PrefixMismatch>,
    /// Whether the tested samples satisfy or contradict the candidate
    pub status: EvidenceStatus,
}

/// Explicit constant-prefix comparison with held-out sample evidence
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConstantPrefixReport {
    /// Requested candidate prefix width
    pub width: usize,
    /// Discovery sample used as the literal prefix reference
    pub reference_sample: u64,
    /// Counts over the discovery split
    pub discovery: PrefixFitSummary,
    /// Counts over the held-out split
    pub holdout: PrefixFitSummary,
    /// Limits on interpreting this candidate result
    pub limitations: Vec<&'static str>,
}

/// Evaluate explicit one, two, and four byte length fields on a stable split
///
/// Candidates cover the first 16 byte offsets, both byte orders, and two stated
/// meanings. The first half is discovery data; the second half remains held out.
/// A candidate match is sample evidence, not proof of a protocol grammar
///
/// # Errors
/// Returns an error when fewer than four samples are supplied, lengths do not
/// vary, identifiers repeat, or any sample or aggregate budget is exceeded
pub fn evaluate_length_fields(
    samples: &[MessageSample<'_>],
) -> Result<LengthFieldReport, MeasurementError> {
    validate_samples(samples, MIN_LAYOUT_SAMPLES)?;
    let first_length = samples.first().map(|sample| sample.bytes.len()).ok_or(
        MeasurementError::InsufficientSamples {
            count: 0,
            minimum: MIN_LAYOUT_SAMPLES,
        },
    )?;
    if samples
        .iter()
        .all(|sample| sample.bytes.len() == first_length)
    {
        return Err(MeasurementError::ConstantSampleLengths);
    }
    let split = samples.len() / 2;
    let discovery = samples
        .get(..split)
        .ok_or(MeasurementError::InsufficientSamples {
            count: samples.len(),
            minimum: MIN_LAYOUT_SAMPLES,
        })?;
    let holdout = samples
        .get(split..)
        .ok_or(MeasurementError::InsufficientSamples {
            count: samples.len(),
            minimum: MIN_LAYOUT_SAMPLES,
        })?;
    // Width one has one byte value, so the opposite byte order adds no information
    let candidates = LengthFieldCandidate::all_candidates()
        .into_iter()
        .map(|candidate| {
            Ok(LengthFieldResult {
                candidate,
                discovery: fit_length_field(discovery, candidate)?,
                holdout: fit_length_field(holdout, candidate)?,
            })
        })
        .collect::<Result<Vec<_>, MeasurementError>>()?;
    Ok(LengthFieldReport {
        candidates,
        discovery_samples: discovery.iter().map(|sample| sample.sample).collect(),
        holdout_samples: holdout.iter().map(|sample| sample.sample).collect(),
        limitations: vec![LAYOUT_LIMITATION, SAMPLE_DEPENDENCE],
    })
}

/// Compare an explicit prefix width against the first discovery sample
///
/// The first half supplies the literal reference. The second half is checked
/// separately so a counterexample remains visible after candidate selection
///
/// # Errors
/// Returns an error for an invalid width, fewer than four samples, a short
/// reference sample, repeated identifiers, or sample byte limits
pub fn evaluate_constant_prefix(
    samples: &[MessageSample<'_>],
    width: usize,
) -> Result<ConstantPrefixReport, MeasurementError> {
    if !(1..=MAX_PREFIX_BYTES).contains(&width) {
        return Err(MeasurementError::InvalidPrefixWidth {
            width,
            maximum: MAX_PREFIX_BYTES,
        });
    }
    validate_samples(samples, MIN_LAYOUT_SAMPLES)?;
    let split = samples.len() / 2;
    let discovery = samples
        .get(..split)
        .ok_or(MeasurementError::InsufficientSamples {
            count: samples.len(),
            minimum: MIN_LAYOUT_SAMPLES,
        })?;
    let holdout = samples
        .get(split..)
        .ok_or(MeasurementError::InsufficientSamples {
            count: samples.len(),
            minimum: MIN_LAYOUT_SAMPLES,
        })?;
    let reference = discovery
        .first()
        .ok_or(MeasurementError::InsufficientSamples {
            count: discovery.len(),
            minimum: 1,
        })?;
    let reference_bytes = reference
        .bytes
        .get(..width)
        .ok_or(MeasurementError::PrefixBaselineTooShort)?;
    Ok(ConstantPrefixReport {
        width,
        reference_sample: reference.sample,
        discovery: fit_prefix(discovery, reference_bytes, width),
        holdout: fit_prefix(holdout, reference_bytes, width),
        limitations: vec![LAYOUT_LIMITATION, SAMPLE_DEPENDENCE],
    })
}

fn fit_length_field(
    samples: &[MessageSample<'_>],
    candidate: LengthFieldCandidate,
) -> Result<FitSummary, MeasurementError> {
    let mut summary = FitSummary {
        sample_count: samples.len(),
        compared: 0,
        supported: 0,
        counterexample_count: 0,
        untestable_samples: 0,
        counterexamples: Vec::new(),
        status: EvidenceStatus::Unresolved,
    };
    for sample in samples {
        let Some((expected_length, observed)) = candidate.values(sample.bytes) else {
            summary.untestable_samples += 1;
            continue;
        };
        let expected =
            u64::try_from(expected_length).map_err(|_| MeasurementError::TotalBytesExceeded {
                length: expected_length,
                maximum: MAX_MEASURED_BYTES,
            })?;
        summary.compared += 1;
        if observed == expected {
            summary.supported += 1;
        } else {
            summary.counterexample_count += 1;
            if summary.counterexamples.len() < MAX_LAYOUT_COUNTEREXAMPLES {
                summary.counterexamples.push(PredictionCounterexample {
                    sample: sample.sample,
                    observed,
                    expected,
                });
            }
        }
    }
    summary.status = fit_status(
        summary.compared,
        summary.counterexample_count,
        summary.untestable_samples,
    );
    Ok(summary)
}

fn fit_prefix(samples: &[MessageSample<'_>], reference: &[u8], width: usize) -> PrefixFitSummary {
    let mut summary = PrefixFitSummary {
        sample_count: samples.len(),
        compared: 0,
        supported: 0,
        counterexample_count: 0,
        untestable_samples: 0,
        counterexamples: Vec::new(),
        status: EvidenceStatus::Unresolved,
    };
    for sample in samples {
        let Some(prefix) = sample.bytes.get(..width) else {
            summary.untestable_samples += 1;
            continue;
        };
        summary.compared += 1;
        if prefix == reference {
            summary.supported += 1;
        } else {
            summary.counterexample_count += 1;
            if summary.counterexamples.len() < MAX_LAYOUT_COUNTEREXAMPLES {
                let difference = reference
                    .iter()
                    .zip(prefix)
                    .position(|(expected, observed)| expected != observed)
                    .unwrap_or(0);
                let expected = reference.get(difference).copied().unwrap_or_default();
                let observed = prefix.get(difference).copied().unwrap_or_default();
                summary.counterexamples.push(PrefixMismatch {
                    sample: sample.sample,
                    offset: difference,
                    expected,
                    observed,
                });
            }
        }
    }
    summary.status = fit_status(
        summary.compared,
        summary.counterexample_count,
        summary.untestable_samples,
    );
    summary
}

const fn fit_status(compared: usize, counterexamples: usize, untestable: usize) -> EvidenceStatus {
    if compared == 0 {
        EvidenceStatus::Unresolved
    } else if counterexamples != 0 {
        EvidenceStatus::ConstraintFailed
    } else if untestable == 0 {
        EvidenceStatus::ConstraintSatisfied
    } else {
        EvidenceStatus::Hypothesis
    }
}

fn validate_samples(samples: &[MessageSample<'_>], minimum: usize) -> Result<(), MeasurementError> {
    if samples.len() < minimum {
        return Err(MeasurementError::InsufficientSamples {
            count: samples.len(),
            minimum,
        });
    }
    if samples.len() > MAX_SAMPLES {
        return Err(MeasurementError::TooManySamples {
            count: samples.len(),
            maximum: MAX_SAMPLES,
        });
    }
    let mut identifiers = HashSet::with_capacity(samples.len());
    let mut total_bytes = 0_usize;
    for sample in samples {
        if sample.sample == 0 || !identifiers.insert(sample.sample) {
            return Err(MeasurementError::InvalidSampleId);
        }
        if sample.bytes.len() > MAX_SAMPLE_BYTES {
            return Err(MeasurementError::SampleTooLarge {
                length: sample.bytes.len(),
                maximum: MAX_SAMPLE_BYTES,
            });
        }
        total_bytes = total_bytes.checked_add(sample.bytes.len()).ok_or(
            MeasurementError::TotalBytesExceeded {
                length: usize::MAX,
                maximum: MAX_MEASURED_BYTES,
            },
        )?;
        if total_bytes > MAX_MEASURED_BYTES {
            return Err(MeasurementError::TotalBytesExceeded {
                length: total_bytes,
                maximum: MAX_MEASURED_BYTES,
            });
        }
    }
    Ok(())
}
