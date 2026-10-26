use super::super::model::{
    RelationalAppliedOutput, RelationalByteRangeLocator, RelationalCounterReset,
    RelationalFalsification, RelationalFit, RelationalFitStatus, RelationalOperationTemplate,
    RelationalParserScope, RelationalRecordSample, RelationalSessionCheck,
    RelationalTransformError, RelationalTransformLimits, RelationalTransformRule,
    RelationalTransformStatus, Selector,
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
type SessionPayloads<'a> = (Vec<u64>, Vec<&'a [u8]>);

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
    let group = one_session_group(samples, limits)?;
    let (seed_sample, seed) = replay_seed(samples, &group, rule, limits)?;
    let (payload_samples, payload_ranges) = replay_payloads(samples, &group, rule, limits)?;
    let work_estimate = transform_work_estimate(
        &payload_ranges,
        seed.len(),
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
        &payload_ranges,
        seed,
        rule.operation,
        rule.counter_reset,
        limits.max_total_bytes,
        work_limit,
    )?;
    let (bytes, work_bytes) = transformed_bytes(transformed)?;
    applied_output(group, seed_sample, payload_samples, bytes, rule, work_bytes)
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
) -> Result<(u64, &'a [u8]), RelationalTransformError> {
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
    Ok((seed_sample.sample, seed))
}

fn replay_payloads<'a>(
    samples: &[RelationalRecordSample<'a>],
    group: &SessionGroup,
    rule: &RelationalTransformRule,
    limits: RelationalTransformLimits,
) -> Result<(Vec<u64>, Vec<&'a [u8]>), RelationalTransformError> {
    let payload_matches = locator_matches(samples, group, None, &rule.payload_locator)?;
    if payload_matches.is_empty() {
        return Err(RelationalTransformError::RuleContradicted(
            "payload locator selected no messages".to_owned(),
        ));
    }
    let mut payload_ranges = Vec::new();
    let mut payload_samples = Vec::new();
    payload_ranges
        .try_reserve_exact(payload_matches.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    payload_samples
        .try_reserve_exact(payload_matches.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    let mut payload_length = 0_usize;
    for sample_index in payload_matches {
        let sample = samples
            .get(sample_index)
            .ok_or(RelationalTransformError::InvalidInput(
                "payload locator references a missing message",
            ))?;
        let range = sample
            .bytes
            .get(rule.payload_locator.value_offset..)
            .filter(|range| !range.is_empty())
            .ok_or_else(|| {
                RelationalTransformError::RuleContradicted(
                    "located payload range is empty".to_owned(),
                )
            })?;
        payload_length = payload_length.checked_add(range.len()).ok_or_else(|| {
            RelationalTransformError::RuleContradicted("payload length overflowed".to_owned())
        })?;
        if payload_length > limits.max_total_bytes {
            return Err(RelationalTransformError::RuleContradicted(format!(
                "payload length {payload_length} exceeds replay limit {}",
                limits.max_total_bytes
            )));
        }
        payload_samples.push(sample.sample);
        payload_ranges.push(range);
    }
    Ok((payload_samples, payload_ranges))
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
    payload_samples: Vec<u64>,
    bytes: Vec<u8>,
    rule: &RelationalTransformRule,
    work_bytes: usize,
) -> Result<RelationalAppliedOutput, RelationalTransformError> {
    let session_order = group.session_order;
    if rule.parser_scope == RelationalParserScope::AcrossSessions {
        return Ok(RelationalAppliedOutput {
            session: group.id,
            session_order,
            seed_sample,
            payload_samples,
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
                payload_samples,
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

pub(super) fn evaluate_split(
    samples: &[RelationalRecordSample<'_>],
    groups: &[SessionGroup],
    indexes: Option<&[SelectorIndex]>,
    rule: &RelationalTransformRule,
    limits: RelationalTransformLimits,
    work_bytes: &mut usize,
) -> Result<RelationalFit, RelationalTransformError> {
    let mut checks = Vec::new();
    checks
        .try_reserve_exact(groups.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    for (group_index, group) in groups.iter().enumerate() {
        let check = check_session(
            samples,
            group,
            indexes.and_then(|items| items.get(group_index)),
            rule,
            limits,
            limits.max_work_bytes.saturating_sub(*work_bytes),
            work_bytes,
        )?;
        checks.push(check);
    }
    Ok(fit_from_checks(checks))
}

fn check_session(
    samples: &[RelationalRecordSample<'_>],
    group: &SessionGroup,
    index: Option<&SelectorIndex>,
    rule: &RelationalTransformRule,
    limits: RelationalTransformLimits,
    work_remaining: usize,
    work_bytes: &mut usize,
) -> Result<RelationalSessionCheck, RelationalTransformError> {
    let inputs = match prepare_session_inputs(samples, group, index, rule, limits)? {
        Ok(inputs) => inputs,
        Err(failure) => return Ok(failure),
    };
    let Some(estimate) = transform_work_estimate(
        &inputs.payload_ranges,
        inputs.seed.len(),
        rule.operation.sha256_counter_xor().counter_width,
        rule.counter_reset,
    ) else {
        return Ok(failed_check(
            group,
            Some(inputs.seed_sample),
            inputs.payload_samples,
            RelationalFalsification::TransformFailed {
                reason: "transform work estimate overflowed".to_owned(),
            },
        ));
    };
    if estimate > work_remaining {
        return Ok(unresolved_check(
            group,
            Some(inputs.seed_sample),
            inputs.payload_samples,
        ));
    }
    let transformed = apply_transform(
        &inputs.payload_ranges,
        inputs.seed,
        rule.operation,
        rule.counter_reset,
        limits.max_total_bytes,
        work_remaining,
    )?;
    *work_bytes = work_bytes.checked_add(transformed.work_bytes).ok_or(
        RelationalTransformError::InvalidPlan("relational work accounting overflowed"),
    )?;
    Ok(check_transformed_session(group, inputs, rule, transformed))
}

struct SessionTransformInputs<'a> {
    seed_sample: u64,
    seed: &'a [u8],
    payload_samples: Vec<u64>,
    payload_ranges: Vec<&'a [u8]>,
}

fn prepare_session_inputs<'a>(
    samples: &[RelationalRecordSample<'a>],
    group: &SessionGroup,
    index: Option<&SelectorIndex>,
    rule: &RelationalTransformRule,
    limits: RelationalTransformLimits,
) -> SessionCheckResult<SessionTransformInputs<'a>> {
    let (seed_sample, seed) = match locate_session_seed(samples, group, index, rule)? {
        Ok(seed) => seed,
        Err(failure) => return Ok(Err(failure)),
    };
    let (payload_samples, payload_ranges) =
        match locate_session_payloads(samples, group, index, rule, limits, seed_sample)? {
            Ok(payloads) => payloads,
            Err(failure) => return Ok(Err(failure)),
        };
    Ok(Ok(SessionTransformInputs {
        seed_sample,
        seed,
        payload_samples,
        payload_ranges,
    }))
}

fn locate_session_seed<'a>(
    samples: &[RelationalRecordSample<'a>],
    group: &SessionGroup,
    index: Option<&SelectorIndex>,
    rule: &RelationalTransformRule,
) -> SessionCheckResult<(u64, &'a [u8])> {
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
    Ok(Ok((seed_sample.sample, seed)))
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
    seed_sample: u64,
) -> SessionCheckResult<SessionPayloads<'a>> {
    let payload_matches = locator_matches(samples, group, index, &rule.payload_locator)?;
    if payload_matches.is_empty() {
        return Ok(Err(failed_check(
            group,
            Some(seed_sample),
            Vec::new(),
            RelationalFalsification::NoPayloadMessages,
        )));
    }
    let mut payload_ranges = Vec::new();
    payload_ranges
        .try_reserve_exact(payload_matches.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    let mut payload_samples = Vec::new();
    payload_samples
        .try_reserve_exact(payload_matches.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    let mut payload_length = 0_usize;
    for sample_index in payload_matches {
        let sample = samples
            .get(sample_index)
            .ok_or(RelationalTransformError::InvalidInput(
                "payload locator references a missing message",
            ))?;
        let Some(payload) = sample.bytes.get(rule.payload_locator.value_offset..) else {
            return Ok(Err(failed_check(
                group,
                Some(seed_sample),
                payload_samples,
                RelationalFalsification::EmptyPayloadRange,
            )));
        };
        if payload.is_empty() {
            return Ok(Err(failed_check(
                group,
                Some(seed_sample),
                payload_samples,
                RelationalFalsification::EmptyPayloadRange,
            )));
        }
        payload_length = payload_length.checked_add(payload.len()).ok_or(
            RelationalTransformError::InvalidInput("located payload length overflowed"),
        )?;
        if payload_length > limits.max_total_bytes {
            return Ok(Err(failed_check(
                group,
                Some(seed_sample),
                payload_samples,
                RelationalFalsification::EmptyPayloadRange,
            )));
        }
        payload_samples.push(sample.sample);
        payload_ranges.push(payload);
    }
    Ok(Ok((payload_samples, payload_ranges)))
}

fn check_transformed_session(
    group: &SessionGroup,
    inputs: SessionTransformInputs<'_>,
    rule: &RelationalTransformRule,
    transformed: TransformOutput,
) -> RelationalSessionCheck {
    let SessionTransformInputs {
        seed_sample,
        payload_samples,
        ..
    } = inputs;
    let Some(output) = transformed.output else {
        if transformed.unresolved_on_budget {
            return unresolved_check(group, Some(seed_sample), payload_samples);
        }
        return failed_check_with_output(
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
        );
    };
    let output_sha256 = sha256(&output);
    if rule.parser_scope == RelationalParserScope::AcrossSessions {
        return RelationalSessionCheck {
            session: group.id.clone(),
            seed_sample: Some(seed_sample),
            payload_samples,
            status: RelationalFitStatus::TransformConstraintsSatisfied,
            output_length: Some(output.len()),
            output_sha256: Some(output_sha256),
            falsification: None,
        };
    }
    validate_session_output(
        group,
        seed_sample,
        payload_samples,
        rule,
        &output,
        output_sha256,
    )
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
    payload_ranges: &[&[u8]],
    seed: &[u8],
    operation_template: RelationalOperationTemplate,
    reset: RelationalCounterReset,
    max_output_bytes: usize,
    work_limit: usize,
) -> Result<TransformOutput, RelationalTransformError> {
    let Some(total_length) = total_payload_length(payload_ranges) else {
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
            for payload in payload_ranges {
                combined.extend_from_slice(payload);
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
            payload_ranges.iter().copied(),
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

fn total_payload_length(payload_ranges: &[&[u8]]) -> Option<usize> {
    payload_ranges
        .iter()
        .try_fold(0_usize, |total, range| total.checked_add(range.len()))
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
    payload_ranges: &[&[u8]],
    seed_length: usize,
    counter_width: CounterWidth,
    reset: RelationalCounterReset,
) -> Option<usize> {
    match reset {
        RelationalCounterReset::Continuous => {
            let total_length = payload_ranges
                .iter()
                .try_fold(0_usize, |total, range| total.checked_add(range.len()))?;
            single_transform_work(total_length, seed_length, counter_width)
        }
        RelationalCounterReset::PerRecord => {
            payload_ranges.iter().try_fold(0_usize, |total, range| {
                total.checked_add(single_transform_work(
                    range.len(),
                    seed_length,
                    counter_width,
                )?)
            })
        }
    }
}

fn single_transform_work(
    input_length: usize,
    seed_length: usize,
    counter_width: CounterWidth,
) -> Option<usize> {
    let blocks = input_length.div_ceil(32);
    let hash_input = seed_length
        .checked_add(counter_width.byte_length())?
        .checked_mul(blocks)?;
    input_length.checked_mul(2)?.checked_add(hash_input)
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
                    RelationalTransformStatus::TransformSupportedAcrossSessions
                } else {
                    RelationalTransformStatus::HeldoutConstraintsSatisfied
                }
            }
            RelationalFitStatus::TransformConstraintsSatisfied => {
                RelationalTransformStatus::TransformSupportedAcrossSessions
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
