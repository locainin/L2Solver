use std::collections::BTreeSet;

use super::{
    ByteOrder, FitSummary, FramingCandidate, FramingCounterexample, FramingKind, LengthMeaning,
    MAX_COUNTEREXAMPLES, ProtocolError, ProtocolLimits,
};
use crate::measurement::LengthFieldCandidate;
use crate::protocol::{
    model::{FramingReport, MessageSample},
    sampling::{sample_refs, split_indices, validate_samples},
};

const MIN_SAMPLES: usize = 4;
const LIMITATIONS: [&str; 3] = [
    "Candidate matches describe only caller-selected message boundaries and do not establish a protocol grammar",
    "Discovery and holdout samples may contain retransmissions or repeated application data",
    "Inferred length prefixes search offsets from zero through the configured inclusive limit and widths 1, 2, and 4; other layouts remain untested",
];

/// Evaluate bounded delimiter, fixed-size, and length-prefix candidates
///
/// Candidates come only from the first half; each is scored separately on
/// discovery and holdout samples. Matching samples are observations, not proof
/// of message grammar
///
/// # Errors
/// Returns an error when sample counts, identifiers, or byte budgets are invalid
pub fn infer_framing(samples: &[MessageSample<'_>]) -> Result<FramingReport, ProtocolError> {
    infer_framing_with_limits(samples, ProtocolLimits::default())
}

/// Evaluate framing hypotheses under caller-selected checked resource budgets
///
/// Context-provided samples are split by complete source/scope/session groups
///
/// # Errors
/// Returns an error when input budgets, sample identity, or holdout groups are invalid
pub fn infer_framing_with_limits(
    samples: &[MessageSample<'_>],
    limits: ProtocolLimits,
) -> Result<FramingReport, ProtocolError> {
    let contextual = validate_samples(samples, MIN_SAMPLES, limits)?;
    let split = split_indices(samples, contextual)?;
    let discovery = sample_refs(samples, &split.discovery)?;
    let holdout = sample_refs(samples, &split.holdout)?;
    let (candidate_kinds, omitted_candidates) =
        generate_candidates(&discovery, limits.max_candidates, limits.max_prefix_offset)?;
    let candidates = candidate_kinds
        .into_iter()
        .map(|kind| FramingCandidate {
            discovery: evaluate_candidate(&kind, &discovery),
            holdout: evaluate_candidate(&kind, &holdout),
            kind,
        })
        .collect();
    Ok(FramingReport {
        candidates,
        omitted_candidates,
        discovery_samples: sample_ids(&discovery),
        holdout_samples: sample_ids(&holdout),
        split_basis: split.basis,
        prefix_offset_limit: limits.max_prefix_offset,
        limitations: LIMITATIONS.to_vec(),
    })
}

fn generate_candidates(
    discovery: &[&MessageSample<'_>],
    maximum: usize,
    max_prefix_offset: usize,
) -> Result<(Vec<FramingKind>, usize), ProtocolError> {
    let mut kinds = Vec::new();
    let delimiters = discovery
        .iter()
        .filter_map(|sample| sample.bytes.last().copied())
        .collect::<BTreeSet<_>>();
    kinds.extend(
        delimiters
            .into_iter()
            .map(|byte| FramingKind::Delimiter { byte }),
    );

    let lengths = discovery
        .iter()
        .map(|sample| sample.bytes.len())
        .collect::<BTreeSet<_>>();
    kinds.extend(
        lengths
            .into_iter()
            .map(|bytes| FramingKind::FixedSize { bytes }),
    );
    let offset_count = max_prefix_offset
        .checked_add(1)
        .ok_or(ProtocolError::InvalidLimits)?;
    let prefix_count = offset_count
        .checked_mul(10)
        .ok_or(ProtocolError::InvalidLimits)?;
    let total_count = kinds
        .len()
        .checked_add(prefix_count)
        .ok_or(ProtocolError::InvalidLimits)?;
    let target = total_count.min(maximum);
    let omitted = total_count - target;
    kinds.truncate(target);
    'offsets: for offset in 0..=max_prefix_offset {
        for width in [1_usize, 2, 4] {
            let byte_orders = if width == 1 {
                &[ByteOrder::BigEndian][..]
            } else {
                &[ByteOrder::BigEndian, ByteOrder::LittleEndian][..]
            };
            for byte_order in byte_orders {
                for meaning in [LengthMeaning::WholeMessage, LengthMeaning::BytesAfterField] {
                    if kinds.len() == target {
                        break 'offsets;
                    }
                    kinds.push(FramingKind::LengthPrefix {
                        offset,
                        width,
                        byte_order: *byte_order,
                        meaning,
                    });
                }
            }
        }
    }
    Ok((kinds, omitted))
}

fn evaluate_candidate(kind: &FramingKind, samples: &[&MessageSample<'_>]) -> FitSummary {
    let mut summary = FitSummary {
        sample_count: samples.len(),
        compared: 0,
        supported: 0,
        counterexample_count: 0,
        untestable_samples: 0,
        counterexamples: Vec::new(),
        omitted_counterexamples: 0,
    };
    for sample in samples {
        let (expected, observed) = match kind {
            FramingKind::Delimiter { byte } => delimiter_fit(*byte, sample.bytes),
            FramingKind::FixedSize { bytes } => (
                u64::try_from(*bytes).ok(),
                u64::try_from(sample.bytes.len()).ok(),
            ),
            FramingKind::LengthPrefix {
                offset,
                width,
                byte_order,
                meaning,
            } => length_prefix_fit(*offset, *width, *byte_order, *meaning, sample.bytes),
        };
        if expected.is_none() {
            summary.untestable_samples += 1;
            continue;
        }
        summary.compared += 1;
        if expected == observed {
            summary.supported += 1;
        } else {
            summary.counterexample_count += 1;
            if summary.counterexamples.len() < MAX_COUNTEREXAMPLES {
                summary.counterexamples.push(FramingCounterexample {
                    sample: sample.sample,
                    expected,
                    observed,
                });
            } else {
                summary.omitted_counterexamples += 1;
            }
        }
    }
    summary
}

fn delimiter_fit(byte: u8, bytes: &[u8]) -> (Option<u64>, Option<u64>) {
    let expected = u64::try_from(bytes.len().saturating_sub(1)).ok();
    let observed = bytes
        .iter()
        .position(|candidate| *candidate == byte)
        .and_then(|value| u64::try_from(value).ok());
    (expected, observed)
}

fn length_prefix_fit(
    offset: usize,
    width: usize,
    byte_order: ByteOrder,
    meaning: LengthMeaning,
    bytes: &[u8],
) -> (Option<u64>, Option<u64>) {
    let candidate = LengthFieldCandidate {
        offset,
        width,
        byte_order,
        meaning,
    };
    candidate
        .values(bytes)
        .map_or((None, None), |(expected, observed)| {
            (u64::try_from(expected).ok(), Some(observed))
        })
}

fn sample_ids(samples: &[&MessageSample<'_>]) -> Vec<u64> {
    samples.iter().map(|sample| sample.sample).collect()
}
