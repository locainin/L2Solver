use super::super::model::{
    RelationalRecordSample, RelationalTransformError, RelationalTransformLimits,
    RelationalTransformRule,
};
use super::{input::SessionGroup, replay};
use crate::derivation::{self, CounterWidth};
use crate::protocol::{
    ByteRange, MessageRole, MessageSample,
    observation::{
        ObservationCohort, ObservationInput, ObservationLimits, ObservationPlan,
        ObservationProvenance, ObservationReport, RegionObservation, SampleRange, observe,
    },
};
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
pub(super) struct PrefixProbeScore {
    pub(super) novelty: usize,
    pub(super) work_bytes: usize,
    pub(super) complete: bool,
}

/// Bound the transform work of one candidate across every selected input message
pub(super) fn maximum_full_candidate_work(
    samples: &[RelationalRecordSample<'_>],
    limits: RelationalTransformLimits,
    counter_widths: &[CounterWidth],
) -> Result<usize, RelationalTransformError> {
    let total_input_bytes = samples
        .iter()
        .try_fold(0_usize, |total, sample| {
            total.checked_add(sample.bytes.len())
        })
        .ok_or(RelationalTransformError::InvalidPlan(
            "candidate work reserve overflowed",
        ))?;
    let counter_width = counter_widths
        .iter()
        .max_by_key(|width| width.byte_length())
        .copied()
        .ok_or(RelationalTransformError::InvalidPlan(
            "candidate work reserve has no counter width",
        ))?;
    let seed_length = limits.max_seed_bytes;
    let base_work =
        derivation::sha256_counter_xor_work(total_input_bytes, seed_length, counter_width).ok_or(
            RelationalTransformError::InvalidPlan("candidate work reserve overflowed"),
        )?;
    let additional_block_bytes = seed_length
        .checked_add(counter_width.byte_length())
        .and_then(|bytes_per_block| bytes_per_block.checked_mul(samples.len()))
        .ok_or(RelationalTransformError::InvalidPlan(
            "candidate work reserve overflowed",
        ))?;
    base_work
        .checked_add(additional_block_bytes)
        .ok_or(RelationalTransformError::InvalidPlan(
            "candidate work reserve overflowed",
        ))
}

/// Rank one frozen candidate from training prefixes without accepting or rejecting it
pub(super) fn score_candidate_prefix(
    samples: &[RelationalRecordSample<'_>],
    discovery_groups: &[SessionGroup],
    rule: &RelationalTransformRule,
    limits: RelationalTransformLimits,
    maximum_work_bytes: usize,
) -> Result<Option<PrefixProbeScore>, RelationalTransformError> {
    let observation_limits = ObservationLimits::default();
    let maximum_prefix_bytes = observation_limits.max_prefix_offset.saturating_add(1);
    let preview = replay::preview_candidate_prefix(
        samples,
        discovery_groups,
        rule,
        limits,
        maximum_prefix_bytes,
        maximum_work_bytes,
    );
    let preview = match preview {
        Ok(Some(preview)) => preview,
        Ok(None)
        | Err(
            RelationalTransformError::RuleContradicted(_) | RelationalTransformError::RuleWorkLimit,
        ) => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };

    let prefix_length = preview
        .messages
        .first()
        .map_or(0, |message| message.input.len());
    let (ranges, ranges_complete) = prefix_ranges(
        &preview.messages,
        prefix_length,
        limits.max_marker_bytes,
        observation_limits.max_region_ranges,
    )?;
    if ranges.is_empty() {
        return Ok(Some(PrefixProbeScore {
            novelty: 0,
            work_bytes: preview.work_bytes,
            complete: ranges_complete,
        }));
    }

    score_prefix_observations(
        &preview,
        ranges,
        prefix_length,
        ranges_complete,
        maximum_work_bytes,
    )
}

fn score_prefix_observations(
    preview: &replay::PrefixProbeOutput<'_>,
    ranges: Vec<SampleRange>,
    prefix_length: usize,
    ranges_complete: bool,
    maximum_work_bytes: usize,
) -> Result<Option<PrefixProbeScore>, RelationalTransformError> {
    let per_pass_input_bytes = prefix_length.checked_mul(preview.messages.len()).ok_or(
        RelationalTransformError::InvalidPlan("prefix probe observation input size overflowed"),
    )?;
    let both_passes_input_bytes =
        per_pass_input_bytes
            .checked_mul(2)
            .ok_or(RelationalTransformError::InvalidPlan(
                "prefix probe observation input size overflowed",
            ))?;
    let work_after_transform = maximum_work_bytes.saturating_sub(preview.work_bytes);
    if both_passes_input_bytes > work_after_transform {
        return Ok(Some(PrefixProbeScore {
            novelty: 0,
            work_bytes: preview.work_bytes,
            complete: false,
        }));
    }
    let observation_units = work_after_transform - both_passes_input_bytes;
    let raw = observe_prefix_stage(
        preview,
        ranges.clone(),
        prefix_length,
        per_pass_input_bytes,
        observation_units / 2,
        false,
    )?;
    let raw_work = observation_work(&raw)?;

    let remaining_units = observation_units.saturating_sub(raw.coverage.work_units);
    let output = observe_prefix_stage(
        preview,
        ranges,
        prefix_length,
        per_pass_input_bytes,
        remaining_units,
        true,
    )?;
    let output_work = observation_work(&output)?;
    let work_bytes = preview
        .work_bytes
        .checked_add(raw_work)
        .and_then(|work| work.checked_add(output_work))
        .ok_or(RelationalTransformError::InvalidPlan(
            "prefix probe work accounting overflowed",
        ))?;

    let complete = ranges_complete && raw.coverage.complete && output.coverage.complete;
    let novelty = if complete {
        novel_repeated_bytes(&raw, &output)
    } else {
        0
    };

    Ok(Some(PrefixProbeScore {
        novelty,
        work_bytes,
        complete,
    }))
}

fn observe_prefix_stage(
    preview: &replay::PrefixProbeOutput<'_>,
    ranges: Vec<SampleRange>,
    prefix_length: usize,
    input_bytes: usize,
    maximum_work_units: usize,
    transformed: bool,
) -> Result<ObservationReport, RelationalTransformError> {
    let stage = if transformed { "output" } else { "input" };
    let identities = observation_identities(&preview.messages, stage)?;
    let inputs = observation_inputs(&preview.messages, &identities, transformed)?;
    let plan = observation_plan(
        ranges,
        &preview.messages,
        prefix_length,
        input_bytes,
        maximum_work_units,
    );
    observe(&inputs, &plan).map_err(|_| {
        let message = if transformed {
            "decoded prefix observation failed"
        } else {
            "raw prefix observation failed"
        };
        RelationalTransformError::InvalidPlan(message)
    })
}

fn observation_identities(
    messages: &[replay::PrefixProbeMessage<'_>],
    stage: &str,
) -> Result<Vec<String>, RelationalTransformError> {
    let mut identities = Vec::new();
    identities
        .try_reserve_exact(messages.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    identities.extend(
        messages
            .iter()
            .map(|message| format!("relational-prefix-{stage}-sample-{}", message.sample)),
    );
    Ok(identities)
}

fn observation_inputs<'a>(
    messages: &'a [replay::PrefixProbeMessage<'_>],
    identities: &'a [String],
    transformed: bool,
) -> Result<Vec<ObservationInput<'a>>, RelationalTransformError> {
    if messages.len() != identities.len() {
        return Err(RelationalTransformError::InvalidInput(
            "prefix observation identities do not match the selected messages",
        ));
    }
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(messages.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    for (message, identity) in messages.iter().zip(identities) {
        let (bytes, range) = if transformed {
            (
                message.output.as_slice(),
                ByteRange {
                    start: 0,
                    end: message.output.len(),
                },
            )
        } else {
            (message.input, message.source_range)
        };
        inputs.push(ObservationInput {
            message: MessageSample {
                sample: message.sample,
                role: MessageRole::Unclassified,
                bytes,
                context: Some(message.context.clone()),
            },
            provenance: ObservationProvenance::Derived { identity, range },
        });
    }
    Ok(inputs)
}

fn prefix_ranges(
    messages: &[replay::PrefixProbeMessage<'_>],
    prefix_length: usize,
    maximum_width: usize,
    maximum_ranges: usize,
) -> Result<(Vec<SampleRange>, bool), RelationalTransformError> {
    let mut ranges = Vec::new();
    ranges
        .try_reserve(maximum_ranges.min(messages.len().saturating_mul(prefix_length)))
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    let mut complete = true;
    'windows: for width in 1..=maximum_width.min(prefix_length) {
        for start in 0..=prefix_length.saturating_sub(width) {
            let end = start
                .checked_add(width)
                .ok_or(RelationalTransformError::InvalidPlan(
                    "prefix observation range overflowed",
                ))?;
            if ranges.len().saturating_add(messages.len()) > maximum_ranges {
                complete = false;
                break 'windows;
            }
            ranges
                .try_reserve_exact(messages.len())
                .map_err(|_| RelationalTransformError::AllocationFailed)?;
            ranges.extend(messages.iter().map(|message| SampleRange {
                sample: message.sample,
                range: ByteRange { start, end },
            }));
        }
    }
    Ok((ranges, complete))
}

fn observation_plan(
    region_ranges: Vec<SampleRange>,
    messages: &[replay::PrefixProbeMessage<'_>],
    prefix_length: usize,
    maximum_input_bytes: usize,
    maximum_work_units: usize,
) -> ObservationPlan {
    let defaults = ObservationLimits::default();
    ObservationPlan {
        region_ranges,
        limits: ObservationLimits {
            max_samples: defaults.max_samples.min(messages.len()),
            max_message_bytes: defaults.max_message_bytes.min(prefix_length),
            max_total_bytes: defaults.max_total_bytes.min(maximum_input_bytes),
            max_prefix_offset: defaults.max_prefix_offset,
            max_hypotheses: defaults.max_hypotheses,
            max_work_units: defaults.max_work_units.min(maximum_work_units),
            max_region_ranges: defaults.max_region_ranges,
            max_region_width: defaults.max_region_width,
            ..defaults
        },
    }
}

fn observation_work(report: &ObservationReport) -> Result<usize, RelationalTransformError> {
    report
        .coverage
        .input_bytes_seen
        .checked_add(report.coverage.work_units)
        .ok_or(RelationalTransformError::InvalidPlan(
            "prefix observation work accounting overflowed",
        ))
}

fn novel_repeated_bytes(raw: &ObservationReport, output: &ObservationReport) -> usize {
    let raw_support = repeated_region_support(raw);
    repeated_region_support(output)
        .into_iter()
        .fold(0_usize, |total, (region, output_support)| {
            let new_support = output_support
                .saturating_sub(raw_support.get(&region).copied().unwrap_or_default());
            let width = region.1.end.saturating_sub(region.1.start);
            total.saturating_add(new_support.saturating_mul(width))
        })
}

type RegionKey = (ObservationCohort, ByteRange);

fn repeated_region_support(report: &ObservationReport) -> BTreeMap<RegionKey, usize> {
    report
        .regions
        .iter()
        .filter_map(|region| {
            region_support(region, &report.byte_observations)
                .map(|support| ((region.cohort.clone(), region.range), support))
        })
        .collect()
}

fn region_support(
    region: &RegionObservation,
    observations: &[crate::protocol::observation::ByteObservation],
) -> Option<usize> {
    region
        .values
        .iter()
        .filter_map(|value| {
            let mut sessions = std::collections::BTreeSet::new();
            for observation_index in &value.observation_indices {
                let observation = observations.get(*observation_index)?;
                let context = observation.context.as_ref()?;
                sessions.insert(context.session);
            }
            (sessions.len() >= 2).then_some(sessions.len())
        })
        .max()
}
