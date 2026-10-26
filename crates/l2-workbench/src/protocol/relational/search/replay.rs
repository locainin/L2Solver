use super::super::model::{
    RelationalAppliedOutput, RelationalByteRangeLocator, RelationalCoordinateBasis,
    RelationalCounterReset, RelationalFalsification, RelationalFit, RelationalFitStatus,
    RelationalLengthField, RelationalOperationTemplate, RelationalOutputMapping,
    RelationalParserScope, RelationalRecordSample, RelationalSessionCheck,
    RelationalSha256CounterXor, RelationalTransformError, RelationalTransformLimits,
    RelationalTransformRule, RelationalTransformStatus, Selector,
};
use super::input::{SelectorIndex, SessionGroup, group_sessions};
use crate::{
    artifact::{ArtifactValidationOutcome, ArtifactValidator},
    derivation::{
        self, CounterWidth, DerivationLimits, DerivationStatus, OperandRef, Operation, Recipe,
    },
    integer::decode_unsigned,
    protocol::ByteOrder,
    sha256,
};

type SessionCheckResult<T> = Result<Result<T, RelationalSessionCheck>, RelationalTransformError>;

struct LocatedPayload<'a> {
    sample: u64,
    sample_index: usize,
    source_range: crate::protocol::ByteRange,
    bytes: &'a [u8],
}

struct LocatedSeed<'a> {
    sample: u64,
    sample_index: usize,
    range: crate::protocol::ByteRange,
    bytes: &'a [u8],
}

pub(super) struct PrefixProbeMessage<'a> {
    pub(super) sample: u64,
    pub(super) context: crate::protocol::MessageContext,
    pub(super) source_range: crate::protocol::ByteRange,
    pub(super) input: &'a [u8],
    pub(super) output: Vec<u8>,
}

pub(super) struct PrefixProbeOutput<'a> {
    pub(super) messages: Vec<PrefixProbeMessage<'a>>,
    pub(super) work_bytes: usize,
}

struct PreparedPrefixSession<'a> {
    seed: LocatedSeed<'a>,
    payload: LocatedPayload<'a>,
}

/// Replay one frozen relational rule against exactly one session and retain its output
///
/// This uses the same byte locators, counter-XOR implementation, resource checks, and
/// structural parser as candidate discovery. The caller must supply the session's own
/// seed-bearing and payload messages; no discovery-session seed is stored in the rule
///
/// # Errors
/// Returns an error when the session does not satisfy the frozen rule or the work limit
/// prevents a complete replay
pub fn apply_relational_transform_rule(
    samples: &[RelationalRecordSample<'_>],
    rule: &RelationalTransformRule,
    limits: RelationalTransformLimits,
    work_limit: usize,
) -> Result<RelationalAppliedOutput, RelationalTransformError> {
    validate_replay_limits(limits)?;
    validate_rule_coordinates(rule)?;
    let group = one_session_group(samples, limits)?;
    let seed = replay_seed(samples, &group, rule, limits)?;
    let payloads = replay_payloads(samples, &group, rule, limits, &seed)?;
    let work_estimate = transform_work_estimate(
        &payloads,
        seed.bytes.len(),
        rule.operation.sha256_counter_xor().counter_width,
        rule.counter_reset,
    )
    .ok_or_else(|| {
        RelationalTransformError::RuleContradicted("transform work estimate overflowed".to_owned())
    })?;
    if work_estimate > work_limit {
        return Err(RelationalTransformError::RuleWorkLimit);
    }
    let transformed = apply_transform(
        &payloads,
        seed.bytes,
        rule.operation,
        rule.counter_reset,
        limits.max_total_bytes,
        work_limit,
    )?;
    let (bytes, work_bytes) = transformed_bytes(transformed)?;
    applied_output(group, seed.sample, &payloads, bytes, rule, work_bytes)
}

fn validate_rule_coordinates(
    rule: &RelationalTransformRule,
) -> Result<(), RelationalTransformError> {
    if rule.seed_locator.coordinate_basis != RelationalCoordinateBasis::MessageStartV1 {
        return Err(RelationalTransformError::InvalidPlan(
            "seed locator coordinates must be message-relative",
        ));
    }
    if rule.payload_locator.coordinate_basis == RelationalCoordinateBasis::SeedRangeEndV1
        && (rule.payload_locator.direction != rule.seed_locator.direction
            || rule
                .seed_locator
                .value_length
                .is_none_or(|length| length == 0)
            || rule.seed_locator.declared_length.is_none())
    {
        return Err(RelationalTransformError::InvalidPlan(
            "seed-relative payload coordinates require the same direction and a declared fixed seed",
        ));
    }
    Ok(())
}

const fn validate_replay_limits(
    limits: RelationalTransformLimits,
) -> Result<(), RelationalTransformError> {
    if limits.max_records_per_session == 0
        || limits.max_record_bytes == 0
        || limits.max_total_bytes == 0
        || limits.max_seed_bytes == 0
    {
        return Err(RelationalTransformError::InvalidPlan(
            "relational replay limits must be positive",
        ));
    }
    Ok(())
}

fn one_session_group(
    samples: &[RelationalRecordSample<'_>],
    limits: RelationalTransformLimits,
) -> Result<SessionGroup, RelationalTransformError> {
    let mut groups = group_sessions(samples, limits)?;
    if groups.len() != 1 {
        return Err(RelationalTransformError::InvalidInput(
            "relational rule replay requires exactly one complete session",
        ));
    }
    groups.pop().ok_or(RelationalTransformError::InvalidInput(
        "relational session group is missing",
    ))
}

fn replay_seed<'a>(
    samples: &[RelationalRecordSample<'a>],
    group: &SessionGroup,
    rule: &RelationalTransformRule,
    limits: RelationalTransformLimits,
) -> Result<LocatedSeed<'a>, RelationalTransformError> {
    let seed_matches = locator_matches(samples, group, None, &rule.seed_locator)?;
    if seed_matches.len() != 1 {
        return Err(RelationalTransformError::RuleContradicted(format!(
            "seed locator selected {} messages",
            seed_matches.len()
        )));
    }
    let seed_index =
        seed_matches
            .first()
            .copied()
            .ok_or(RelationalTransformError::InvalidInput(
                "seed locator count changed during replay",
            ))?;
    let seed_sample = samples
        .get(seed_index)
        .ok_or(RelationalTransformError::InvalidInput(
            "seed locator references a missing message",
        ))?;
    let seed_length = rule.seed_locator.value_length.ok_or_else(|| {
        RelationalTransformError::RuleContradicted(
            "seed locator has no fixed seed length".to_owned(),
        )
    })?;
    if seed_length > limits.max_seed_bytes {
        return Err(RelationalTransformError::RuleContradicted(format!(
            "seed length {seed_length} exceeds replay limit {}",
            limits.max_seed_bytes
        )));
    }
    if let Some(field) = rule.seed_locator.declared_length {
        let observed = declared_length_value(seed_sample.bytes, field);
        if observed != u64::try_from(seed_length).ok() {
            return Err(RelationalTransformError::RuleContradicted(format!(
                "seed length field decoded to {observed:?}, expected {seed_length}"
            )));
        }
    }
    let seed_end = rule
        .seed_locator
        .value_offset
        .checked_add(seed_length)
        .ok_or_else(|| {
            RelationalTransformError::RuleContradicted("seed range overflowed".to_owned())
        })?;
    let seed = seed_sample
        .bytes
        .get(rule.seed_locator.value_offset..seed_end)
        .ok_or_else(|| {
            RelationalTransformError::RuleContradicted(
                "located seed range is unavailable".to_owned(),
            )
        })?;
    Ok(LocatedSeed {
        sample: seed_sample.sample,
        sample_index: seed_index,
        range: crate::protocol::ByteRange {
            start: rule.seed_locator.value_offset,
            end: seed_end,
        },
        bytes: seed,
    })
}

fn replay_payloads<'a>(
    samples: &[RelationalRecordSample<'a>],
    group: &SessionGroup,
    rule: &RelationalTransformRule,
    limits: RelationalTransformLimits,
    seed: &LocatedSeed<'_>,
) -> Result<Vec<LocatedPayload<'a>>, RelationalTransformError> {
    let payload_matches = payload_locator_matches(samples, group, None, rule, seed)?;
    if payload_matches.is_empty() {
        return Err(RelationalTransformError::RuleContradicted(
            "payload locator selected no messages".to_owned(),
        ));
    }
    let mut payloads = Vec::new();
    payloads
        .try_reserve_exact(payload_matches.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    let mut payload_length = 0_usize;
    for sample_index in payload_matches {
        let sample = samples
            .get(sample_index)
            .ok_or(RelationalTransformError::InvalidInput(
                "payload locator references a missing message",
            ))?;
        let source_range = payload_source_range(&rule.payload_locator, seed, sample.bytes.len())
            .ok_or_else(|| {
                RelationalTransformError::RuleContradicted(
                    "located payload range is unavailable".to_owned(),
                )
            })?;
        let bytes = sample
            .bytes
            .get(source_range.start..source_range.end)
            .filter(|range| !range.is_empty())
            .ok_or_else(|| {
                RelationalTransformError::RuleContradicted(
                    "located payload range is empty".to_owned(),
                )
            })?;
        payload_length = payload_length.checked_add(bytes.len()).ok_or_else(|| {
            RelationalTransformError::RuleContradicted("payload length overflowed".to_owned())
        })?;
        if payload_length > limits.max_total_bytes {
            return Err(RelationalTransformError::RuleContradicted(format!(
                "payload length {payload_length} exceeds replay limit {}",
                limits.max_total_bytes
            )));
        }
        if rule.payload_locator.declared_length.is_some() {
            let expected = bytes.len();
            let observed =
                locator_declared_length_value(sample.bytes, &rule.payload_locator, seed.range.end);
            if observed != u64::try_from(expected).ok() {
                return Err(RelationalTransformError::RuleContradicted(format!(
                    "payload length field decoded to {observed:?}, expected {expected}"
                )));
            }
        }
        payloads.push(LocatedPayload {
            sample: sample.sample,
            sample_index,
            source_range,
            bytes,
        });
    }
    Ok(payloads)
}

/// Preview the same bounded prefix from every discovery session after checking full ranges
pub(super) fn preview_candidate_prefix<'a>(
    samples: &[RelationalRecordSample<'a>],
    discovery_groups: &[SessionGroup],
    rule: &RelationalTransformRule,
    limits: RelationalTransformLimits,
    maximum_prefix_bytes: usize,
    maximum_work_bytes: usize,
) -> Result<Option<PrefixProbeOutput<'a>>, RelationalTransformError> {
    if maximum_prefix_bytes == 0 {
        return Ok(None);
    }
    let parameters = rule.operation.sha256_counter_xor();
    let Some((discovery, common_prefix_length)) = prepare_prefix_discovery(
        samples,
        discovery_groups,
        rule,
        limits,
        maximum_prefix_bytes,
        parameters.counter_width,
        parameters.initial_counter,
    )?
    else {
        return Ok(None);
    };
    let transform_prefix_work =
        prefix_transform_work(&discovery, common_prefix_length, parameters.counter_width)?;
    if transform_prefix_work > maximum_work_bytes {
        return Ok(None);
    }
    let Some(messages) =
        transform_prefix_discovery(samples, discovery, parameters, common_prefix_length)?
    else {
        return Ok(None);
    };
    Ok(Some(PrefixProbeOutput {
        messages,
        work_bytes: transform_prefix_work,
    }))
}

fn prepare_prefix_discovery<'a>(
    samples: &[RelationalRecordSample<'a>],
    discovery_groups: &[SessionGroup],
    rule: &RelationalTransformRule,
    limits: RelationalTransformLimits,
    maximum_prefix_bytes: usize,
    counter_width: CounterWidth,
    initial_counter: u64,
) -> Result<Option<(Vec<PreparedPrefixSession<'a>>, usize)>, RelationalTransformError> {
    let mut discovery = Vec::new();
    discovery
        .try_reserve_exact(discovery_groups.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    let mut common_prefix_length = maximum_prefix_bytes;

    for group in discovery_groups {
        let Some(prepared) =
            prepare_prefix_session(samples, group, rule, limits, counter_width, initial_counter)?
        else {
            return Ok(None);
        };
        common_prefix_length = common_prefix_length.min(prepared.payload.bytes.len());
        discovery.push(prepared);
    }
    if common_prefix_length == 0 {
        return Ok(None);
    }
    Ok(Some((discovery, common_prefix_length)))
}

fn prefix_transform_work(
    discovery: &[PreparedPrefixSession<'_>],
    prefix_length: usize,
    counter_width: CounterWidth,
) -> Result<usize, RelationalTransformError> {
    discovery
        .iter()
        .try_fold(0_usize, |total, prepared| {
            let work = derivation::sha256_counter_xor_work(
                prefix_length,
                prepared.seed.bytes.len(),
                counter_width,
            )?;
            total.checked_add(work)
        })
        .ok_or(RelationalTransformError::InvalidPlan(
            "prefix probe work estimate overflowed",
        ))
}

fn transform_prefix_discovery<'a>(
    samples: &[RelationalRecordSample<'a>],
    discovery: Vec<PreparedPrefixSession<'a>>,
    parameters: RelationalSha256CounterXor,
    common_prefix_length: usize,
) -> Result<Option<Vec<PrefixProbeMessage<'a>>>, RelationalTransformError> {
    let mut messages = Vec::new();
    messages
        .try_reserve_exact(discovery.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    for prepared in discovery {
        let input = prepared.payload.bytes.get(..common_prefix_length).ok_or(
            RelationalTransformError::InvalidInput(
                "prefix probe range is unavailable after preflight",
            ),
        )?;
        let output = match derivation::preview_sha256_counter_xor(
            input,
            prepared.seed.bytes,
            parameters.initial_counter,
            parameters.counter_width,
            parameters.counter_byte_order,
            parameters.seed_order,
        ) {
            Ok(output) => output,
            Err(crate::derivation::StepFailure::AllocationFailed) => {
                return Err(RelationalTransformError::AllocationFailed);
            }
            Err(_) => return Ok(None),
        };
        let sample = samples.get(prepared.payload.sample_index).ok_or(
            RelationalTransformError::InvalidInput("prefix probe references a missing sample"),
        )?;
        let source_end = prepared
            .payload
            .source_range
            .start
            .checked_add(common_prefix_length)
            .ok_or(RelationalTransformError::InvalidInput(
                "prefix probe source range overflowed",
            ))?;
        messages.push(PrefixProbeMessage {
            sample: prepared.payload.sample,
            context: sample.context.clone(),
            source_range: crate::protocol::ByteRange {
                start: prepared.payload.source_range.start,
                end: source_end,
            },
            input,
            output,
        });
    }
    Ok(Some(messages))
}

fn prepare_prefix_session<'a>(
    samples: &[RelationalRecordSample<'a>],
    group: &SessionGroup,
    rule: &RelationalTransformRule,
    limits: RelationalTransformLimits,
    counter_width: CounterWidth,
    initial_counter: u64,
) -> Result<Option<PreparedPrefixSession<'a>>, RelationalTransformError> {
    let seed = match replay_seed(samples, group, rule, limits) {
        Ok(seed) => seed,
        Err(RelationalTransformError::RuleContradicted(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let payloads = match replay_payloads(samples, group, rule, limits, &seed) {
        Ok(payloads) => payloads,
        Err(RelationalTransformError::RuleContradicted(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    if payloads.len() != 1
        || !capacity_supports_full_payloads(
            &payloads,
            initial_counter,
            counter_width,
            rule.counter_reset,
        )
    {
        return Ok(None);
    }
    Ok(Some(PreparedPrefixSession {
        seed,
        payload: payloads
            .into_iter()
            .next()
            .ok_or(RelationalTransformError::InvalidInput(
                "prefix payload disappeared after selection",
            ))?,
    }))
}

fn capacity_supports_full_payloads(
    payloads: &[LocatedPayload<'_>],
    initial_counter: u64,
    counter_width: CounterWidth,
    reset: RelationalCounterReset,
) -> bool {
    match reset {
        RelationalCounterReset::Continuous => payloads
            .iter()
            .try_fold(0_usize, |total, payload| {
                total.checked_add(payload.bytes.len())
            })
            .is_some_and(|length| {
                derivation::validate_sha256_counter_xor_capacity(
                    length,
                    initial_counter,
                    counter_width,
                )
                .is_ok()
            }),
        RelationalCounterReset::PerRecord => payloads.iter().all(|payload| {
            derivation::validate_sha256_counter_xor_capacity(
                payload.bytes.len(),
                initial_counter,
                counter_width,
            )
            .is_ok()
        }),
    }
}

fn payload_locator_matches(
    samples: &[RelationalRecordSample<'_>],
    group: &SessionGroup,
    index: Option<&SelectorIndex>,
    rule: &RelationalTransformRule,
    seed: &LocatedSeed<'_>,
) -> Result<Vec<usize>, RelationalTransformError> {
    if rule.payload_locator.coordinate_basis == RelationalCoordinateBasis::MessageStartV1 {
        return locator_matches(samples, group, index, &rule.payload_locator);
    }

    let marker_start =
        offset_for_locator(&rule.payload_locator, seed.range.end, true).ok_or_else(|| {
            RelationalTransformError::RuleContradicted("locator coordinate overflowed".to_owned())
        })?;
    let matches = samples.get(seed.sample_index).is_some_and(|sample| {
        let direction_matches_payload = sample.context.direction == rule.payload_locator.direction;
        let same_seed_sample = sample.sample == seed.sample;
        let marker_matches = sample
            .bytes
            .get(marker_start..)
            .and_then(|tail| tail.get(..rule.payload_locator.marker.len()))
            == Some(rule.payload_locator.marker.as_slice());
        direction_matches_payload && same_seed_sample && marker_matches
    });
    if !matches {
        return Ok(Vec::new());
    }
    Ok(vec![seed.sample_index])
}

fn resolve_coordinate_offset(
    basis: RelationalCoordinateBasis,
    offset: usize,
    seed_end: usize,
) -> Result<usize, RelationalTransformError> {
    let base = match basis {
        RelationalCoordinateBasis::MessageStartV1 => 0,
        RelationalCoordinateBasis::SeedRangeEndV1 => seed_end,
    };
    base.checked_add(offset).ok_or_else(|| {
        RelationalTransformError::RuleContradicted("locator coordinate overflowed".to_owned())
    })
}

fn payload_source_range(
    locator: &RelationalByteRangeLocator,
    seed: &LocatedSeed<'_>,
    sample_length: usize,
) -> Option<crate::protocol::ByteRange> {
    let start = offset_for_locator(locator, seed.range.end, false)?;
    let end = match locator.value_length {
        Some(length) => start.checked_add(length)?,
        None => sample_length,
    };
    (start < end).then_some(crate::protocol::ByteRange { start, end })
}

const fn offset_for_locator(
    locator: &RelationalByteRangeLocator,
    seed_end: usize,
    marker: bool,
) -> Option<usize> {
    let offset = if marker {
        locator.marker_offset
    } else {
        locator.value_offset
    };
    match locator.coordinate_basis {
        RelationalCoordinateBasis::MessageStartV1 => Some(offset),
        RelationalCoordinateBasis::SeedRangeEndV1 => seed_end.checked_add(offset),
    }
}

fn locator_declared_length_value(
    bytes: &[u8],
    locator: &RelationalByteRangeLocator,
    seed_end: usize,
) -> Option<u64> {
    let field = locator.declared_length?;
    let offset =
        resolve_coordinate_offset(locator.coordinate_basis, field.offset, seed_end).ok()?;
    declared_length_value(bytes, RelationalLengthField { offset, ..field })
}

fn transformed_bytes(
    transformed: TransformOutput,
) -> Result<(Vec<u8>, usize), RelationalTransformError> {
    let TransformOutput {
        output,
        work_bytes,
        unresolved_on_budget,
        failure,
    } = transformed;
    output.map(|bytes| (bytes, work_bytes)).ok_or_else(|| {
        if unresolved_on_budget {
            RelationalTransformError::RuleWorkLimit
        } else {
            RelationalTransformError::RuleContradicted(
                failure.unwrap_or_else(|| "canonical transform produced no output".to_owned()),
            )
        }
    })
}

fn applied_output(
    group: SessionGroup,
    seed_sample: u64,
    payloads: &[LocatedPayload<'_>],
    bytes: Vec<u8>,
    rule: &RelationalTransformRule,
    work_bytes: usize,
) -> Result<RelationalAppliedOutput, RelationalTransformError> {
    let session_order = group.session_order;
    let payload_mappings = payload_output_mappings(payloads)?;
    validate_output_coverage(&payload_mappings, bytes.len())?;
    if rule.parser_scope == RelationalParserScope::AcrossSessions {
        return Ok(RelationalAppliedOutput {
            session: group.id,
            session_order,
            seed_sample,
            payload_mappings,
            bytes,
            parser_validation_deferred: true,
            work_bytes,
        });
    }
    match ArtifactValidator::default().validate_as(rule.parser_format, &bytes) {
        ArtifactValidationOutcome::Validated { range, .. }
            if range.offset == 0 && range.length == bytes.len() =>
        {
            Ok(RelationalAppliedOutput {
                session: group.id,
                session_order,
                seed_sample,
                payload_mappings,
                bytes,
                parser_validation_deferred: false,
                work_bytes,
            })
        }
        outcome => Err(RelationalTransformError::RuleContradicted(format!(
            "exact parser check failed: {outcome:?}"
        ))),
    }
}

fn payload_output_mappings(
    payloads: &[LocatedPayload<'_>],
) -> Result<Vec<RelationalOutputMapping>, RelationalTransformError> {
    let mut mappings = Vec::new();
    mappings
        .try_reserve_exact(payloads.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    let mut start = 0_usize;
    for payload in payloads {
        let end = start.checked_add(payload.bytes.len()).ok_or(
            RelationalTransformError::InvalidInput("transformed payload range overflowed"),
        )?;
        mappings.push(RelationalOutputMapping {
            sample: payload.sample,
            source_range: payload.source_range,
            output_range: crate::protocol::ByteRange { start, end },
        });
        start = end;
    }
    Ok(mappings)
}

fn payload_sample_ids(
    payloads: &[LocatedPayload<'_>],
) -> Result<Vec<u64>, RelationalTransformError> {
    let mut samples = Vec::new();
    samples
        .try_reserve_exact(payloads.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    samples.extend(payloads.iter().map(|payload| payload.sample));
    Ok(samples)
}

fn validate_output_coverage(
    mappings: &[RelationalOutputMapping],
    output_length: usize,
) -> Result<(), RelationalTransformError> {
    let mut next_output_start = 0_usize;
    for mapping in mappings {
        if mapping.output_range.start != next_output_start
            || mapping.output_range.end <= mapping.output_range.start
        {
            return Err(RelationalTransformError::InvalidInput(
                "relational output mappings do not cover the transformed bytes",
            ));
        }
        next_output_start = mapping.output_range.end;
    }
    if mappings.is_empty() || next_output_start != output_length {
        return Err(RelationalTransformError::InvalidInput(
            "relational output mappings do not cover the transformed bytes",
        ));
    }
    Ok(())
}

pub(super) fn evaluate_split(
    samples: &[RelationalRecordSample<'_>],
    groups: &[SessionGroup],
    indexes: Option<&[SelectorIndex]>,
    rule: &RelationalTransformRule,
    limits: RelationalTransformLimits,
    work_bytes: &mut usize,
    capture_outputs: bool,
) -> Result<EvaluatedSplit, RelationalTransformError> {
    let mut checks = Vec::new();
    checks
        .try_reserve_exact(groups.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    let mut outputs = Vec::new();
    if capture_outputs {
        outputs
            .try_reserve_exact(groups.len())
            .map_err(|_| RelationalTransformError::AllocationFailed)?;
    }
    for (group_index, group) in groups.iter().enumerate() {
        let context = SessionCheckContext {
            samples,
            index: indexes.and_then(|items| items.get(group_index)),
            rule,
            limits,
            work_remaining: limits.max_work_bytes.saturating_sub(*work_bytes),
            capture_output: capture_outputs,
        };
        let evaluated = check_session(group, context, work_bytes)?;
        checks.push(evaluated.check);
        if let Some(output) = evaluated.output {
            outputs.push(output);
        }
    }
    Ok(EvaluatedSplit {
        fit: fit_from_checks(checks),
        outputs,
    })
}

pub(super) struct EvaluatedSplit {
    pub(super) fit: RelationalFit,
    pub(super) outputs: Vec<RelationalAppliedOutput>,
}

struct EvaluatedSessionCheck {
    check: RelationalSessionCheck,
    output: Option<RelationalAppliedOutput>,
}

#[derive(Clone, Copy)]
struct SessionCheckContext<'a, 'bytes> {
    samples: &'a [RelationalRecordSample<'bytes>],
    index: Option<&'a SelectorIndex>,
    rule: &'a RelationalTransformRule,
    limits: RelationalTransformLimits,
    work_remaining: usize,
    capture_output: bool,
}

fn check_session(
    group: &SessionGroup,
    context: SessionCheckContext<'_, '_>,
    work_bytes: &mut usize,
) -> Result<EvaluatedSessionCheck, RelationalTransformError> {
    let inputs = match prepare_session_inputs(
        context.samples,
        group,
        context.index,
        context.rule,
        context.limits,
    )? {
        Ok(inputs) => inputs,
        Err(check) => {
            return Ok(EvaluatedSessionCheck {
                check,
                output: None,
            });
        }
    };
    let Some(estimate) = transform_work_estimate(
        &inputs.payloads,
        inputs.seed.bytes.len(),
        context.rule.operation.sha256_counter_xor().counter_width,
        context.rule.counter_reset,
    ) else {
        return Ok(EvaluatedSessionCheck {
            check: failed_check(
                group,
                Some(inputs.seed.sample),
                payload_sample_ids(&inputs.payloads)?,
                RelationalFalsification::TransformFailed {
                    reason: "transform work estimate overflowed".to_owned(),
                },
            ),
            output: None,
        });
    };
    if estimate > context.work_remaining {
        return Ok(EvaluatedSessionCheck {
            check: unresolved_check(
                group,
                Some(inputs.seed.sample),
                payload_sample_ids(&inputs.payloads)?,
            ),
            output: None,
        });
    }
    let transformed = apply_transform(
        &inputs.payloads,
        inputs.seed.bytes,
        context.rule.operation,
        context.rule.counter_reset,
        context.limits.max_total_bytes,
        context.work_remaining,
    )?;
    *work_bytes = work_bytes.checked_add(transformed.work_bytes).ok_or(
        RelationalTransformError::InvalidPlan("relational work accounting overflowed"),
    )?;
    let output_mappings = if context.capture_output {
        Some(payload_output_mappings(&inputs.payloads)?)
    } else {
        None
    };
    check_transformed_session(group, inputs, context.rule, transformed, output_mappings)
}

struct SessionTransformInputs<'a> {
    seed: LocatedSeed<'a>,
    payloads: Vec<LocatedPayload<'a>>,
}

fn prepare_session_inputs<'a>(
    samples: &[RelationalRecordSample<'a>],
    group: &SessionGroup,
    index: Option<&SelectorIndex>,
    rule: &RelationalTransformRule,
    limits: RelationalTransformLimits,
) -> SessionCheckResult<SessionTransformInputs<'a>> {
    let seed = match locate_session_seed(samples, group, index, rule)? {
        Ok(seed) => seed,
        Err(failure) => return Ok(Err(failure)),
    };
    let payloads = match locate_session_payloads(samples, group, index, rule, limits, &seed)? {
        Ok(payloads) => payloads,
        Err(failure) => return Ok(Err(failure)),
    };
    Ok(Ok(SessionTransformInputs { seed, payloads }))
}

fn locate_session_seed<'a>(
    samples: &[RelationalRecordSample<'a>],
    group: &SessionGroup,
    index: Option<&SelectorIndex>,
    rule: &RelationalTransformRule,
) -> SessionCheckResult<LocatedSeed<'a>> {
    validate_rule_coordinates(rule)?;
    let seed_matches = locator_matches(samples, group, index, &rule.seed_locator)?;
    if seed_matches.len() != 1 {
        return Ok(Err(failed_check(
            group,
            seed_matches
                .first()
                .and_then(|sample_index| samples.get(*sample_index))
                .map(|sample| sample.sample),
            Vec::new(),
            RelationalFalsification::SeedMessageCount {
                observed: seed_matches.len(),
            },
        )));
    }
    let Some(seed_sample_index) = seed_matches.first().copied() else {
        return Err(RelationalTransformError::InvalidInput(
            "seed locator count changed during session evaluation",
        ));
    };
    let seed_sample =
        samples
            .get(seed_sample_index)
            .ok_or(RelationalTransformError::InvalidInput(
                "seed locator references a missing message",
            ))?;
    if let Some(field) = rule.seed_locator.declared_length {
        let expected = rule.seed_locator.value_length.unwrap_or_default();
        let observed = declared_length_value(seed_sample.bytes, field);
        if observed != u64::try_from(expected).ok() {
            return Ok(Err(failed_check(
                group,
                Some(seed_sample.sample),
                Vec::new(),
                RelationalFalsification::SeedLengthMismatch { expected, observed },
            )));
        }
    }
    let Some(seed_end) = rule
        .seed_locator
        .value_offset
        .checked_add(rule.seed_locator.value_length.unwrap_or_default())
    else {
        return Ok(Err(failed_check(
            group,
            Some(seed_sample.sample),
            Vec::new(),
            RelationalFalsification::SeedRangeUnavailable,
        )));
    };
    let Some(seed) = seed_sample
        .bytes
        .get(rule.seed_locator.value_offset..seed_end)
    else {
        return Ok(Err(failed_check(
            group,
            Some(seed_sample.sample),
            Vec::new(),
            RelationalFalsification::SeedRangeUnavailable,
        )));
    };
    Ok(Ok(LocatedSeed {
        sample: seed_sample.sample,
        sample_index: seed_sample_index,
        range: crate::protocol::ByteRange {
            start: rule.seed_locator.value_offset,
            end: seed_end,
        },
        bytes: seed,
    }))
}

fn declared_length_value(
    bytes: &[u8],
    field: super::super::model::RelationalLengthField,
) -> Option<u64> {
    let end = field.offset.checked_add(field.width.byte_length())?;
    decode_unsigned(
        bytes.get(field.offset..end)?,
        field.byte_order == ByteOrder::LittleEndian,
    )
}

fn locate_session_payloads<'a>(
    samples: &[RelationalRecordSample<'a>],
    group: &SessionGroup,
    index: Option<&SelectorIndex>,
    rule: &RelationalTransformRule,
    limits: RelationalTransformLimits,
    seed: &LocatedSeed<'_>,
) -> SessionCheckResult<Vec<LocatedPayload<'a>>> {
    let payload_matches = payload_locator_matches(samples, group, index, rule, seed)?;
    if payload_matches.is_empty() {
        return Ok(Err(failed_check(
            group,
            Some(seed.sample),
            Vec::new(),
            RelationalFalsification::NoPayloadMessages,
        )));
    }
    let mut payloads = Vec::new();
    payloads
        .try_reserve_exact(payload_matches.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    let mut payload_length = 0_usize;
    for sample_index in payload_matches {
        let sample = samples
            .get(sample_index)
            .ok_or(RelationalTransformError::InvalidInput(
                "payload locator references a missing message",
            ))?;
        let Some(source_range) =
            payload_source_range(&rule.payload_locator, seed, sample.bytes.len())
        else {
            return Ok(Err(failed_check(
                group,
                Some(seed.sample),
                payload_sample_ids(&payloads)?,
                RelationalFalsification::EmptyPayloadRange,
            )));
        };
        let Some(payload) = sample.bytes.get(source_range.start..source_range.end) else {
            return Ok(Err(failed_check(
                group,
                Some(seed.sample),
                payload_sample_ids(&payloads)?,
                RelationalFalsification::EmptyPayloadRange,
            )));
        };
        if payload.is_empty() {
            return Ok(Err(failed_check(
                group,
                Some(seed.sample),
                payload_sample_ids(&payloads)?,
                RelationalFalsification::EmptyPayloadRange,
            )));
        }
        payload_length = payload_length.checked_add(payload.len()).ok_or(
            RelationalTransformError::InvalidInput("located payload length overflowed"),
        )?;
        if payload_length > limits.max_total_bytes {
            return Ok(Err(failed_check(
                group,
                Some(seed.sample),
                payload_sample_ids(&payloads)?,
                RelationalFalsification::EmptyPayloadRange,
            )));
        }
        if rule.payload_locator.declared_length.is_some() {
            let observed =
                locator_declared_length_value(sample.bytes, &rule.payload_locator, seed.range.end);
            if observed != u64::try_from(payload.len()).ok() {
                return Ok(Err(failed_check(
                    group,
                    Some(seed.sample),
                    payload_sample_ids(&payloads)?,
                    RelationalFalsification::PayloadLengthMismatch {
                        expected: payload.len(),
                        observed,
                    },
                )));
            }
        }
        payloads.push(LocatedPayload {
            sample: sample.sample,
            sample_index,
            source_range,
            bytes: payload,
        });
    }
    Ok(Ok(payloads))
}

fn check_transformed_session(
    group: &SessionGroup,
    inputs: SessionTransformInputs<'_>,
    rule: &RelationalTransformRule,
    transformed: TransformOutput,
    output_mappings: Option<Vec<RelationalOutputMapping>>,
) -> Result<EvaluatedSessionCheck, RelationalTransformError> {
    let SessionTransformInputs { seed, payloads } = inputs;
    let seed_sample = seed.sample;
    let Some(output) = transformed.output else {
        return check_missing_transform_output(group, seed_sample, &payloads, transformed);
    };
    let output_sha256 = sha256(&output);
    let payload_samples = payload_sample_ids(&payloads)?;
    if let Some(mappings) = output_mappings.as_deref() {
        validate_output_coverage(mappings, output.len())?;
    }
    if rule.parser_scope == RelationalParserScope::AcrossSessions {
        return Ok(EvaluatedSessionCheck {
            check: RelationalSessionCheck {
                session: group.id.clone(),
                seed_sample: Some(seed_sample),
                payload_samples,
                status: RelationalFitStatus::TransformConstraintsSatisfied,
                output_length: Some(output.len()),
                output_sha256: Some(output_sha256),
                falsification: None,
            },
            output: output_mappings.map(|mappings| {
                captured_session_output(
                    group,
                    seed_sample,
                    mappings,
                    output,
                    transformed.work_bytes,
                    true,
                )
            }),
        });
    }
    let check = validate_session_output(
        group,
        seed_sample,
        payload_samples,
        rule,
        &output,
        output_sha256,
    );
    let retained_output = if check.status == RelationalFitStatus::ConstraintsSatisfied {
        output_mappings.map(|mappings| {
            captured_session_output(
                group,
                seed_sample,
                mappings,
                output,
                transformed.work_bytes,
                false,
            )
        })
    } else {
        None
    };
    Ok(EvaluatedSessionCheck {
        check,
        output: retained_output,
    })
}

fn check_missing_transform_output(
    group: &SessionGroup,
    seed_sample: u64,
    payloads: &[LocatedPayload<'_>],
    transformed: TransformOutput,
) -> Result<EvaluatedSessionCheck, RelationalTransformError> {
    let payload_samples = payload_sample_ids(payloads)?;
    let check = if transformed.unresolved_on_budget {
        unresolved_check(group, Some(seed_sample), payload_samples)
    } else {
        failed_check_with_output(
            group,
            Some(seed_sample),
            payload_samples,
            None,
            None,
            RelationalFalsification::TransformFailed {
                reason: transformed
                    .failure
                    .unwrap_or_else(|| "transform failed".to_owned()),
            },
        )
    };
    Ok(EvaluatedSessionCheck {
        check,
        output: None,
    })
}

fn captured_session_output(
    group: &SessionGroup,
    seed_sample: u64,
    payload_mappings: Vec<RelationalOutputMapping>,
    bytes: Vec<u8>,
    work_bytes: usize,
    parser_validation_deferred: bool,
) -> RelationalAppliedOutput {
    RelationalAppliedOutput {
        session: group.id.clone(),
        session_order: group.session_order,
        seed_sample,
        payload_mappings,
        bytes,
        parser_validation_deferred,
        work_bytes,
    }
}

fn validate_session_output(
    group: &SessionGroup,
    seed_sample: u64,
    payload_samples: Vec<u64>,
    rule: &RelationalTransformRule,
    output: &[u8],
    output_sha256: String,
) -> RelationalSessionCheck {
    let validation = ArtifactValidator::default().validate_as(rule.parser_format, output);
    match validation {
        ArtifactValidationOutcome::Validated { range, .. }
            if range.offset == 0 && range.length == output.len() =>
        {
            RelationalSessionCheck {
                session: group.id.clone(),
                seed_sample: Some(seed_sample),
                payload_samples,
                status: RelationalFitStatus::ConstraintsSatisfied,
                output_length: Some(output.len()),
                output_sha256: Some(output_sha256),
                falsification: None,
            }
        }
        ArtifactValidationOutcome::Validated { range, .. } => failed_check_with_output(
            group,
            Some(seed_sample),
            payload_samples,
            Some(output.len()),
            Some(output_sha256),
            RelationalFalsification::ParserRangeMismatch {
                format: rule.parser_format,
                offset: range.offset,
                length: range.length,
            },
        ),
        ArtifactValidationOutcome::BoundaryUnproven { .. } => failed_check_with_output(
            group,
            Some(seed_sample),
            payload_samples,
            Some(output.len()),
            Some(output_sha256),
            RelationalFalsification::BoundaryUnproven {
                format: rule.parser_format,
            },
        ),
        ArtifactValidationOutcome::Rejected { reason, .. } => failed_check_with_output(
            group,
            Some(seed_sample),
            payload_samples,
            Some(output.len()),
            Some(output_sha256),
            RelationalFalsification::ParserRejected {
                format: rule.parser_format,
                reason,
            },
        ),
        ArtifactValidationOutcome::Omitted { reason, .. } => RelationalSessionCheck {
            session: group.id.clone(),
            seed_sample: Some(seed_sample),
            payload_samples,
            status: RelationalFitStatus::UnresolvedOnBudget,
            output_length: Some(output.len()),
            output_sha256: Some(output_sha256),
            falsification: Some(RelationalFalsification::ParserOmitted {
                format: rule.parser_format,
                reason,
            }),
        },
        ArtifactValidationOutcome::Unsupported { .. } => failed_check_with_output(
            group,
            Some(seed_sample),
            payload_samples,
            Some(output.len()),
            Some(output_sha256),
            RelationalFalsification::ParserUnsupported {
                format: rule.parser_format,
            },
        ),
    }
}

struct TransformOutput {
    output: Option<Vec<u8>>,
    work_bytes: usize,
    unresolved_on_budget: bool,
    failure: Option<String>,
}

fn apply_transform(
    payloads: &[LocatedPayload<'_>],
    seed: &[u8],
    operation_template: RelationalOperationTemplate,
    reset: RelationalCounterReset,
    max_output_bytes: usize,
    work_limit: usize,
) -> Result<TransformOutput, RelationalTransformError> {
    let Some(total_length) = payloads.iter().try_fold(0_usize, |total, payload| {
        total.checked_add(payload.bytes.len())
    }) else {
        return Ok(TransformOutput::failed("payload length overflowed"));
    };
    if total_length > max_output_bytes {
        return Ok(TransformOutput::failed(
            "payload exceeds the configured output bound",
        ));
    }
    let recipe = transform_recipe(seed, operation_template);
    match reset {
        RelationalCounterReset::Continuous => {
            let mut combined = Vec::new();
            combined
                .try_reserve_exact(total_length)
                .map_err(|_| RelationalTransformError::AllocationFailed)?;
            for payload in payloads {
                combined.extend_from_slice(payload.bytes);
            }
            run_transform_ranges(
                std::iter::once(combined.as_slice()),
                &recipe,
                total_length,
                seed.len(),
                max_output_bytes,
                work_limit,
            )
        }
        RelationalCounterReset::PerRecord => run_transform_ranges(
            payloads.iter().map(|payload| payload.bytes),
            &recipe,
            total_length,
            seed.len(),
            max_output_bytes,
            work_limit,
        ),
    }
}

impl TransformOutput {
    fn failed(reason: &str) -> Self {
        Self {
            output: None,
            work_bytes: 0,
            unresolved_on_budget: false,
            failure: Some(reason.to_owned()),
        }
    }
}

fn transform_recipe(seed: &[u8], operation_template: RelationalOperationTemplate) -> Recipe {
    let operation = operation_template.sha256_counter_xor();
    Recipe {
        steps: vec![Operation::Sha256CounterXor {
            seed: OperandRef::from(seed.to_vec()),
            initial_counter: operation.initial_counter,
            counter_width: operation.counter_width,
            counter_byte_order: operation.counter_byte_order,
            seed_order: operation.seed_order,
        }],
        constraints: Vec::new(),
    }
}

fn run_transform_ranges<'a>(
    ranges: impl IntoIterator<Item = &'a [u8]>,
    recipe: &Recipe,
    total_length: usize,
    seed_length: usize,
    max_output_bytes: usize,
    work_limit: usize,
) -> Result<TransformOutput, RelationalTransformError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(total_length)
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    let mut work_bytes = 0_usize;
    for input in ranges {
        let remaining = work_limit.saturating_sub(work_bytes);
        let limits = DerivationLimits {
            max_input_bytes: max_output_bytes,
            max_output_bytes,
            max_intermediate_bytes: max_output_bytes,
            max_work_bytes: remaining,
            max_steps: 1,
            max_constraints: 1,
            max_recipe_parameter_bytes: seed_length,
        };
        let report = derivation::run_with_limits(input, recipe, limits)?;
        work_bytes = work_bytes.checked_add(report.work_bytes).ok_or(
            RelationalTransformError::InvalidPlan("relational transform work overflowed"),
        )?;
        if report.status != DerivationStatus::Completed {
            let reason = report.steps.first().map_or_else(
                || "canonical derivation did not complete".to_owned(),
                |step| format!("{:?}", step.status),
            );
            let unresolved_on_budget = reason.contains("WorkBudgetExceeded");
            return Ok(TransformOutput {
                output: None,
                work_bytes,
                unresolved_on_budget,
                failure: Some(reason),
            });
        }
        output.extend_from_slice(&report.output);
    }
    Ok(TransformOutput {
        output: Some(output),
        work_bytes,
        unresolved_on_budget: false,
        failure: None,
    })
}

fn transform_work_estimate(
    payloads: &[LocatedPayload<'_>],
    seed_length: usize,
    counter_width: CounterWidth,
    reset: RelationalCounterReset,
) -> Option<usize> {
    match reset {
        RelationalCounterReset::Continuous => {
            let total_length = payloads.iter().try_fold(0_usize, |total, payload| {
                total.checked_add(payload.bytes.len())
            })?;
            single_transform_work(total_length, seed_length, counter_width)
        }
        RelationalCounterReset::PerRecord => payloads.iter().try_fold(0_usize, |total, payload| {
            total.checked_add(single_transform_work(
                payload.bytes.len(),
                seed_length,
                counter_width,
            )?)
        }),
    }
}

fn single_transform_work(
    input_length: usize,
    seed_length: usize,
    counter_width: CounterWidth,
) -> Option<usize> {
    derivation::sha256_counter_xor_work(input_length, seed_length, counter_width)
}

fn locator_matches(
    samples: &[RelationalRecordSample<'_>],
    group: &SessionGroup,
    index: Option<&SelectorIndex>,
    locator: &RelationalByteRangeLocator,
) -> Result<Vec<usize>, RelationalTransformError> {
    let selector = Selector {
        direction: locator.direction,
        marker_offset: locator.marker_offset,
        marker: locator.marker.clone(),
    };
    if let Some(index) = index {
        let Some(matches) = index.get(&selector) else {
            return Ok(Vec::new());
        };
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(matches.len())
            .map_err(|_| RelationalTransformError::AllocationFailed)?;
        retained.extend_from_slice(matches);
        return Ok(retained);
    }
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(group.sample_indices.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    for sample_index in &group.sample_indices {
        let matches = samples.get(*sample_index).is_some_and(|sample| {
            sample.context.direction == locator.direction
                && sample
                    .bytes
                    .get(locator.marker_offset..)
                    .and_then(|tail| tail.get(..locator.marker.len()))
                    == Some(locator.marker.as_slice())
        });
        if matches {
            retained.push(*sample_index);
        }
    }
    Ok(retained)
}

fn failed_check(
    group: &SessionGroup,
    seed_sample: Option<u64>,
    payload_samples: Vec<u64>,
    falsification: RelationalFalsification,
) -> RelationalSessionCheck {
    failed_check_with_output(
        group,
        seed_sample,
        payload_samples,
        None,
        None,
        falsification,
    )
}

fn failed_check_with_output(
    group: &SessionGroup,
    seed_sample: Option<u64>,
    payload_samples: Vec<u64>,
    output_length: Option<usize>,
    output_sha256: Option<String>,
    falsification: RelationalFalsification,
) -> RelationalSessionCheck {
    RelationalSessionCheck {
        session: group.id.clone(),
        seed_sample,
        payload_samples,
        status: RelationalFitStatus::Contradicted,
        output_length,
        output_sha256,
        falsification: Some(falsification),
    }
}

fn unresolved_check(
    group: &SessionGroup,
    seed_sample: Option<u64>,
    payload_samples: Vec<u64>,
) -> RelationalSessionCheck {
    RelationalSessionCheck {
        session: group.id.clone(),
        seed_sample,
        payload_samples,
        status: RelationalFitStatus::UnresolvedOnBudget,
        output_length: None,
        output_sha256: None,
        falsification: None,
    }
}

fn fit_from_checks(checks: Vec<RelationalSessionCheck>) -> RelationalFit {
    let mut supported_sessions = Vec::new();
    let mut contradicted_sessions = Vec::new();
    let mut unresolved_sessions = Vec::new();
    for check in &checks {
        match check.status {
            RelationalFitStatus::ConstraintsSatisfied
            | RelationalFitStatus::TransformConstraintsSatisfied => {
                supported_sessions.push(check.session.clone());
            }
            RelationalFitStatus::Contradicted => {
                contradicted_sessions.push(check.session.clone());
            }
            RelationalFitStatus::UnresolvedOnBudget => {
                unresolved_sessions.push(check.session.clone());
            }
            RelationalFitStatus::NotEvaluated => {}
        }
    }
    let status = if !contradicted_sessions.is_empty() {
        RelationalFitStatus::Contradicted
    } else if !unresolved_sessions.is_empty() {
        RelationalFitStatus::UnresolvedOnBudget
    } else if !supported_sessions.is_empty() && supported_sessions.len() == checks.len() {
        if checks
            .iter()
            .any(|check| check.status == RelationalFitStatus::TransformConstraintsSatisfied)
        {
            RelationalFitStatus::TransformConstraintsSatisfied
        } else {
            RelationalFitStatus::ConstraintsSatisfied
        }
    } else {
        RelationalFitStatus::NotEvaluated
    };
    RelationalFit {
        status,
        supported_sessions,
        contradicted_sessions,
        unresolved_sessions,
        checks,
    }
}

pub(super) const fn empty_fit(status: RelationalFitStatus) -> RelationalFit {
    RelationalFit {
        status,
        supported_sessions: Vec::new(),
        contradicted_sessions: Vec::new(),
        unresolved_sessions: Vec::new(),
        checks: Vec::new(),
    }
}

pub(super) fn candidate_status(
    discovery: &RelationalFit,
    heldout: &RelationalFit,
    parser_scope: RelationalParserScope,
) -> RelationalTransformStatus {
    match discovery.status {
        RelationalFitStatus::Contradicted | RelationalFitStatus::NotEvaluated => {
            RelationalTransformStatus::DiscoveryContradicted
        }
        RelationalFitStatus::UnresolvedOnBudget => RelationalTransformStatus::UnresolvedOnBudget,
        RelationalFitStatus::ConstraintsSatisfied
        | RelationalFitStatus::TransformConstraintsSatisfied
            if heldout.checks.is_empty() && heldout.status == RelationalFitStatus::NotEvaluated =>
        {
            RelationalTransformStatus::DiscoveryOnlyHypothesis
        }
        RelationalFitStatus::ConstraintsSatisfied
        | RelationalFitStatus::TransformConstraintsSatisfied => match heldout.status {
            RelationalFitStatus::ConstraintsSatisfied => {
                if parser_scope == RelationalParserScope::AcrossSessions {
                    RelationalTransformStatus::AwaitingAcrossSessionValidation
                } else {
                    RelationalTransformStatus::HeldoutConstraintsSatisfied
                }
            }
            RelationalFitStatus::TransformConstraintsSatisfied => {
                RelationalTransformStatus::AwaitingAcrossSessionValidation
            }
            RelationalFitStatus::Contradicted => {
                RelationalTransformStatus::ContradictedByHeldoutSession
            }
            RelationalFitStatus::UnresolvedOnBudget | RelationalFitStatus::NotEvaluated => {
                RelationalTransformStatus::UnresolvedOnBudget
            }
        },
    }
}
