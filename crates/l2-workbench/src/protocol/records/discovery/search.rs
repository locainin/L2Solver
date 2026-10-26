use super::super::RecordWorkBudget;
use super::super::{ParsedRecord, RecordError, RecordInput, RecordParseReport, RecordSchema};
use super::error::RecordDiscoveryError;
use super::model::{
    CandidateKey, RecordDiscoveryLimits, RecordDiscoveryPartition, RecordDiscoveryValidationBasis,
    RecordSchemaDiscoveryReport, RecordSchemaDiscoverySpace, RecordSchemaFalsification,
    RecordSchemaHypothesis, seen_candidate,
};
use std::collections::HashSet;
use std::ops::ControlFlow;

pub(in crate::protocol::records) type RecordSchemaParseObserver<'observer> =
    dyn FnMut(
            &RecordSchemaHypothesis,
            &[RecordParseReport],
            &[RecordParseReport],
        ) -> ControlFlow<()>
        + 'observer;

/// Discover exact record layouts from caller-framed training and held-out messages
///
/// Each candidate describes a complete repeated-record list using caller-selected offsets and
/// count modes. The strict parser must consume every message. Discovery reports only parse
/// counts; assembly remains separate because these inputs have no capture or conversation context
/// Empty holdout input selects training-only validation, which the report identifies explicitly
///
/// # Errors
/// Rejects empty domains or training input, invalid limits, and aggregate resource excess
pub fn discover_record_schemas(
    training_messages: &[&[u8]],
    held_out_messages: &[&[u8]],
    space: &RecordSchemaDiscoverySpace,
    limits: RecordDiscoveryLimits,
) -> Result<RecordSchemaDiscoveryReport, RecordDiscoveryError> {
    space.validate()?;
    limits.validate()?;
    validate_messages(training_messages, held_out_messages, limits)?;
    let training_inputs = own_inputs(training_messages)?;
    let held_out_inputs = own_inputs(held_out_messages)?;
    let training_refs = input_refs(&training_inputs)?;
    let held_out_refs = input_refs(&held_out_inputs)?;
    discover_record_schemas_from_validated_inputs(
        &training_refs,
        &held_out_refs,
        space.candidate_count(),
        limits,
        |ordinal, _work| Ok(space.candidate_at(ordinal)),
        None,
        None,
    )
    .map(|(report, _)| report)
}

pub(in crate::protocol::records) fn discover_record_schemas_from_candidates_with_work<F>(
    training_inputs: &[&RecordInput<'_>],
    held_out_inputs: &[&RecordInput<'_>],
    candidate_combinations: Option<usize>,
    limits: RecordDiscoveryLimits,
    candidate_at: F,
    work: Option<&mut RecordWorkBudget>,
) -> Result<RecordSchemaDiscoveryReport, RecordDiscoveryError>
where
    F: FnMut(
        usize,
        &mut Option<&mut RecordWorkBudget>,
    ) -> Result<Option<RecordSchema>, RecordDiscoveryError>,
{
    discover_record_schemas_from_inputs_impl(
        training_inputs,
        held_out_inputs,
        candidate_combinations,
        limits,
        candidate_at,
        None,
        work,
    )
    .map(|(report, _)| report)
}

pub(in crate::protocol::records) fn discover_record_schemas_from_candidates_observed<F>(
    training_inputs: &[&RecordInput<'_>],
    held_out_inputs: &[&RecordInput<'_>],
    candidate_combinations: Option<usize>,
    limits: RecordDiscoveryLimits,
    candidate_at: F,
    work: Option<&mut RecordWorkBudget>,
    observer: &mut RecordSchemaParseObserver<'_>,
) -> Result<(RecordSchemaDiscoveryReport, bool), RecordDiscoveryError>
where
    F: FnMut(
        usize,
        &mut Option<&mut RecordWorkBudget>,
    ) -> Result<Option<RecordSchema>, RecordDiscoveryError>,
{
    discover_record_schemas_from_inputs_impl(
        training_inputs,
        held_out_inputs,
        candidate_combinations,
        limits,
        candidate_at,
        Some(observer),
        work,
    )
}

fn discover_record_schemas_from_inputs_impl<F>(
    training_inputs: &[&RecordInput<'_>],
    held_out_inputs: &[&RecordInput<'_>],
    candidate_combinations: Option<usize>,
    limits: RecordDiscoveryLimits,
    candidate_at: F,
    observer: Option<&mut RecordSchemaParseObserver<'_>>,
    work: Option<&mut RecordWorkBudget>,
) -> Result<(RecordSchemaDiscoveryReport, bool), RecordDiscoveryError>
where
    F: FnMut(
        usize,
        &mut Option<&mut RecordWorkBudget>,
    ) -> Result<Option<RecordSchema>, RecordDiscoveryError>,
{
    limits.validate()?;
    validate_inputs(training_inputs, held_out_inputs, limits)?;

    discover_record_schemas_from_validated_inputs(
        training_inputs,
        held_out_inputs,
        candidate_combinations,
        limits,
        candidate_at,
        observer,
        work,
    )
}

fn discover_record_schemas_from_validated_inputs<F>(
    training_inputs: &[&RecordInput<'_>],
    held_out_inputs: &[&RecordInput<'_>],
    candidate_combinations: Option<usize>,
    limits: RecordDiscoveryLimits,
    candidate_at: F,
    observer: Option<&mut RecordSchemaParseObserver<'_>>,
    mut work: Option<&mut RecordWorkBudget>,
) -> Result<(RecordSchemaDiscoveryReport, bool), RecordDiscoveryError>
where
    F: FnMut(
        usize,
        &mut Option<&mut RecordWorkBudget>,
    ) -> Result<Option<RecordSchema>, RecordDiscoveryError>,
{
    let validation_basis = if held_out_inputs.is_empty() {
        RecordDiscoveryValidationBasis::TrainingOnly
    } else {
        RecordDiscoveryValidationBasis::HeldOutMessages
    };
    let mut report = discovery_report(candidate_combinations, validation_basis);
    let stopped_by_observer = evaluate_combinations(
        &mut report,
        CandidateSearchInputs {
            training_inputs,
            held_out_inputs,
            limits,
            candidate_combinations,
        },
        candidate_at,
        observer,
        &mut work,
    )?;
    report.unexamined_combinations = candidate_combinations
        .map(|total| {
            total
                .checked_sub(report.examined_combinations)
                .ok_or(RecordDiscoveryError::InvalidLimits)
        })
        .transpose()?;
    report.search_exhaustive_within_plan = report.unexamined_combinations == Some(0)
        && !report.work_limit_reached
        && report.resource_limited_candidates == 0;
    report.report_details_complete = report.omitted_survivors == 0
        && report.omitted_falsification_examples == 0
        && !report.work_limit_reached
        && report.resource_limited_candidates == 0;
    Ok((report, stopped_by_observer))
}

fn validate_messages(
    training_messages: &[&[u8]],
    held_out_messages: &[&[u8]],
    limits: RecordDiscoveryLimits,
) -> Result<(), RecordDiscoveryError> {
    validate_message_count(training_messages.len(), held_out_messages.len(), limits)?;
    validate_input_lengths(
        training_messages
            .iter()
            .chain(held_out_messages)
            .map(|message| message.len()),
        limits,
    )
}

fn validate_inputs(
    training_inputs: &[&RecordInput<'_>],
    held_out_inputs: &[&RecordInput<'_>],
    limits: RecordDiscoveryLimits,
) -> Result<(), RecordDiscoveryError> {
    validate_message_count(training_inputs.len(), held_out_inputs.len(), limits)?;
    validate_input_lengths(
        training_inputs
            .iter()
            .chain(held_out_inputs)
            .map(|input| input.bytes().len()),
        limits,
    )
}

fn validate_message_count(
    training_count: usize,
    held_out_count: usize,
    limits: RecordDiscoveryLimits,
) -> Result<(), RecordDiscoveryError> {
    // One training message can support structural parsing; more messages add corroboration
    if training_count == 0 {
        return Err(RecordDiscoveryError::NoTrainingMessages {
            held_out: held_out_count,
        });
    }
    let message_count = training_count.checked_add(held_out_count).ok_or(
        RecordDiscoveryError::TooManyMessages {
            count: usize::MAX,
            maximum: limits.max_messages,
        },
    )?;
    if message_count > limits.max_messages {
        return Err(RecordDiscoveryError::TooManyMessages {
            count: message_count,
            maximum: limits.max_messages,
        });
    }
    if message_count > limits.record_limits.max_records {
        return Err(RecordDiscoveryError::RecordOperation(
            RecordError::TooManyRecords {
                count: u64::try_from(message_count).unwrap_or(u64::MAX),
                maximum: limits.record_limits.max_records,
            },
        ));
    }
    Ok(())
}

fn validate_input_lengths(
    lengths: impl Iterator<Item = usize>,
    limits: RecordDiscoveryLimits,
) -> Result<(), RecordDiscoveryError> {
    // One shared input ceiling applies across training and held-out messages
    let mut total_input_bytes = 0_usize;
    for input_length in lengths {
        total_input_bytes = total_input_bytes.checked_add(input_length).ok_or(
            RecordDiscoveryError::RecordOperation(RecordError::InputTooLarge {
                length: usize::MAX,
                maximum: limits.record_limits.max_input_bytes,
            }),
        )?;
        if input_length > limits.record_limits.max_input_bytes
            || total_input_bytes > limits.record_limits.max_input_bytes
        {
            return Err(RecordDiscoveryError::RecordOperation(
                RecordError::InputTooLarge {
                    length: total_input_bytes,
                    maximum: limits.record_limits.max_input_bytes,
                },
            ));
        }
    }
    Ok(())
}

const fn discovery_report(
    candidate_combinations: Option<usize>,
    validation_basis: RecordDiscoveryValidationBasis,
) -> RecordSchemaDiscoveryReport {
    RecordSchemaDiscoveryReport {
        validation_basis,
        candidate_combinations,
        examined_combinations: 0,
        unexamined_combinations: None,
        search_exhaustive_within_plan: false,
        report_details_complete: true,
        work_limit_reached: false,
        resource_limited_candidates: 0,
        surviving: Vec::new(),
        omitted_survivors: 0,
        falsifications: Vec::new(),
        falsified_count: 0,
        omitted_falsification_examples: 0,
    }
}

#[derive(Clone, Copy)]
struct CandidateSearchInputs<'refs, 'record, 'bytes> {
    training_inputs: &'refs [&'record RecordInput<'bytes>],
    held_out_inputs: &'refs [&'record RecordInput<'bytes>],
    limits: RecordDiscoveryLimits,
    candidate_combinations: Option<usize>,
}

#[derive(Clone, Copy)]
enum CandidateProgress {
    Continue,
    Stop,
}

fn evaluate_combinations<F>(
    report: &mut RecordSchemaDiscoveryReport,
    inputs: CandidateSearchInputs<'_, '_, '_>,
    mut candidate_at: F,
    mut observer: Option<&mut RecordSchemaParseObserver<'_>>,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<bool, RecordDiscoveryError>
where
    F: FnMut(
        usize,
        &mut Option<&mut RecordWorkBudget>,
    ) -> Result<Option<RecordSchema>, RecordDiscoveryError>,
{
    let combination_budget = inputs
        .candidate_combinations
        .unwrap_or(inputs.limits.max_candidates)
        .min(inputs.limits.max_candidates);
    let mut seen = HashSet::<CandidateKey>::new();
    let mut stopped_by_observer = false;
    for ordinal in 0..combination_budget {
        let Some(schema) = next_schema(report, ordinal, &mut candidate_at, work)? else {
            break;
        };
        match evaluate_schema(
            report,
            &inputs,
            schema,
            &mut seen,
            &mut observer,
            work,
            &mut stopped_by_observer,
        )? {
            CandidateProgress::Continue => {}
            CandidateProgress::Stop => break,
        }
    }
    Ok(stopped_by_observer)
}

fn next_schema<F>(
    report: &mut RecordSchemaDiscoveryReport,
    ordinal: usize,
    candidate_at: &mut F,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<Option<RecordSchema>, RecordDiscoveryError>
where
    F: FnMut(
        usize,
        &mut Option<&mut RecordWorkBudget>,
    ) -> Result<Option<RecordSchema>, RecordDiscoveryError>,
{
    if !charge_work(work, std::mem::size_of::<RecordSchema>()) {
        report.work_limit_reached = true;
        return Ok(None);
    }
    match candidate_at(ordinal, work) {
        Ok(Some(schema)) => Ok(Some(schema)),
        Ok(None) => Err(RecordDiscoveryError::InvalidLimits),
        Err(RecordDiscoveryError::RecordOperation(RecordError::WorkLimitExceeded { .. })) => {
            report.work_limit_reached = true;
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn evaluate_schema(
    report: &mut RecordSchemaDiscoveryReport,
    inputs: &CandidateSearchInputs<'_, '_, '_>,
    schema: RecordSchema,
    seen: &mut HashSet<CandidateKey>,
    observer: &mut Option<&mut RecordSchemaParseObserver<'_>>,
    work: &mut Option<&mut RecordWorkBudget>,
    stopped_by_observer: &mut bool,
) -> Result<CandidateProgress, RecordDiscoveryError> {
    report.examined_combinations = report
        .examined_combinations
        .checked_add(1)
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    // Repeated entries in caller domains describe the same schema only once
    if !charge_work(work, std::mem::size_of::<RecordSchema>()) {
        report.examined_combinations = report.examined_combinations.saturating_sub(1);
        report.work_limit_reached = true;
        return Ok(CandidateProgress::Stop);
    }
    let is_new = match seen_candidate(seen, &schema) {
        Ok(is_new) => is_new,
        Err(RecordDiscoveryError::RecordOperation(RecordError::AllocationFailed)) => {
            report.examined_combinations = report.examined_combinations.saturating_sub(1);
            report.resource_limited_candidates = report
                .resource_limited_candidates
                .checked_add(1)
                .ok_or(RecordDiscoveryError::InvalidLimits)?;
            return Ok(CandidateProgress::Stop);
        }
        Err(error) => return Err(error),
    };
    if !is_new {
        return Ok(CandidateProgress::Continue);
    }
    let evaluation = evaluate_candidate(
        &schema,
        inputs.training_inputs,
        inputs.held_out_inputs,
        inputs.limits.record_limits,
        observer.is_some(),
        work,
    )?;
    record_candidate_evaluation(
        report,
        inputs,
        schema,
        evaluation,
        observer,
        work,
        stopped_by_observer,
    )
}

fn record_candidate_evaluation(
    report: &mut RecordSchemaDiscoveryReport,
    inputs: &CandidateSearchInputs<'_, '_, '_>,
    schema: RecordSchema,
    evaluation: CandidateEvaluation,
    observer: &mut Option<&mut RecordSchemaParseObserver<'_>>,
    work: &mut Option<&mut RecordWorkBudget>,
    stopped_by_observer: &mut bool,
) -> Result<CandidateProgress, RecordDiscoveryError> {
    match evaluation {
        CandidateEvaluation::WorkLimit => {
            report.examined_combinations = report.examined_combinations.saturating_sub(1);
            report.work_limit_reached = true;
            Ok(CandidateProgress::Stop)
        }
        CandidateEvaluation::ResourceLimited { stop_search } => {
            report.examined_combinations = report.examined_combinations.saturating_sub(1);
            report.resource_limited_candidates = report
                .resource_limited_candidates
                .checked_add(1)
                .ok_or(RecordDiscoveryError::InvalidLimits)?;
            Ok(if stop_search {
                CandidateProgress::Stop
            } else {
                CandidateProgress::Continue
            })
        }
        CandidateEvaluation::Falsified {
            partition,
            message_index,
            error,
        } => {
            let continue_search = record_falsification(
                report,
                inputs.limits.max_falsifications,
                schema,
                partition,
                message_index,
                error,
                work,
            )?;
            Ok(if continue_search {
                CandidateProgress::Continue
            } else {
                CandidateProgress::Stop
            })
        }
        CandidateEvaluation::Survives {
            training_record_count,
            held_out_record_count,
            parsed_reports,
        } => {
            let hypothesis = RecordSchemaHypothesis {
                schema,
                training_message_count: inputs.training_inputs.len(),
                held_out_message_count: inputs.held_out_inputs.len(),
                training_record_count,
                held_out_record_count,
            };
            record_survivor(
                report,
                inputs,
                hypothesis,
                parsed_reports.as_ref(),
                observer,
                work,
                stopped_by_observer,
            )
        }
    }
}

fn record_survivor(
    report: &mut RecordSchemaDiscoveryReport,
    inputs: &CandidateSearchInputs<'_, '_, '_>,
    hypothesis: RecordSchemaHypothesis,
    parsed_reports: Option<&(Vec<RecordParseReport>, Vec<RecordParseReport>)>,
    observer: &mut Option<&mut RecordSchemaParseObserver<'_>>,
    work: &mut Option<&mut RecordWorkBudget>,
    stopped_by_observer: &mut bool,
) -> Result<CandidateProgress, RecordDiscoveryError> {
    if let (Some(observer), Some((training_reports, held_out_reports))) =
        (observer.as_deref_mut(), parsed_reports)
        && matches!(
            observer(&hypothesis, training_reports, held_out_reports),
            ControlFlow::Break(())
        )
    {
        *stopped_by_observer = true;
    }
    if report.surviving.len() >= inputs.limits.max_survivors {
        report.omitted_survivors = report
            .omitted_survivors
            .checked_add(1)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        return Ok(if *stopped_by_observer {
            CandidateProgress::Stop
        } else {
            CandidateProgress::Continue
        });
    }
    if !charge_work(work, std::mem::size_of::<RecordSchemaHypothesis>()) {
        report.omitted_survivors = report
            .omitted_survivors
            .checked_add(1)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        report.work_limit_reached = true;
        return Ok(CandidateProgress::Stop);
    }
    if report.surviving.try_reserve(1).is_err() {
        report.omitted_survivors = report
            .omitted_survivors
            .checked_add(1)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        report.resource_limited_candidates = report
            .resource_limited_candidates
            .checked_add(1)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        return Ok(CandidateProgress::Stop);
    }
    report.surviving.push(hypothesis);
    Ok(if *stopped_by_observer {
        CandidateProgress::Stop
    } else {
        CandidateProgress::Continue
    })
}

enum CandidateEvaluation {
    WorkLimit,
    ResourceLimited {
        stop_search: bool,
    },
    Falsified {
        partition: RecordDiscoveryPartition,
        message_index: usize,
        error: RecordError,
    },
    Survives {
        training_record_count: usize,
        held_out_record_count: usize,
        parsed_reports: Option<(Vec<RecordParseReport>, Vec<RecordParseReport>)>,
    },
}

fn evaluate_candidate(
    schema: &RecordSchema,
    training_inputs: &[&RecordInput<'_>],
    held_out_inputs: &[&RecordInput<'_>],
    record_limits: super::super::RecordLimits,
    capture_reports: bool,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<CandidateEvaluation, RecordDiscoveryError> {
    let mut totals = ParseTotals::default();
    let training = match evaluate_partition(
        schema,
        training_inputs,
        RecordDiscoveryPartition::Training,
        record_limits,
        capture_reports,
        &mut totals,
        work,
    )? {
        PartitionEvaluation::Complete(partition) => partition,
        PartitionEvaluation::Rejected(evaluation) => return Ok(evaluation),
    };
    let held_out = match evaluate_partition(
        schema,
        held_out_inputs,
        RecordDiscoveryPartition::HeldOut,
        record_limits,
        capture_reports,
        &mut totals,
        work,
    )? {
        PartitionEvaluation::Complete(partition) => partition,
        PartitionEvaluation::Rejected(evaluation) => return Ok(evaluation),
    };
    Ok(CandidateEvaluation::Survives {
        training_record_count: training.record_count,
        held_out_record_count: held_out.record_count,
        parsed_reports: capture_reports.then_some((training.reports, held_out.reports)),
    })
}

#[derive(Default)]
struct ParseTotals {
    record_count: usize,
    metadata_bytes: usize,
}

struct ParsedPartition {
    record_count: usize,
    reports: Vec<RecordParseReport>,
}

enum PartitionEvaluation {
    Complete(ParsedPartition),
    Rejected(CandidateEvaluation),
}

fn evaluate_partition(
    schema: &RecordSchema,
    inputs: &[&RecordInput<'_>],
    partition: RecordDiscoveryPartition,
    record_limits: super::super::RecordLimits,
    capture_reports: bool,
    totals: &mut ParseTotals,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<PartitionEvaluation, RecordDiscoveryError> {
    let mut record_count = 0_usize;
    let mut reports = Vec::new();
    for (message_index, input) in inputs.iter().enumerate() {
        if capture_reports && reports.try_reserve_exact(1).is_err() {
            return Ok(PartitionEvaluation::Rejected(
                CandidateEvaluation::ResourceLimited { stop_search: true },
            ));
        }
        let parsed = parse_input(input, schema, record_limits, work);
        match parsed {
            Ok(report) => {
                let count = add_parse_totals(
                    &report,
                    &mut totals.record_count,
                    &mut totals.metadata_bytes,
                    record_limits,
                )?;
                record_count = record_count
                    .checked_add(count)
                    .ok_or(RecordDiscoveryError::InvalidLimits)?;
                if capture_reports {
                    reports.push(report);
                }
            }
            Err(error) => {
                if matches!(&error, RecordError::WorkLimitExceeded { .. }) {
                    return Ok(PartitionEvaluation::Rejected(
                        CandidateEvaluation::WorkLimit,
                    ));
                }
                if parser_resource_limit(&error) {
                    return Ok(PartitionEvaluation::Rejected(
                        CandidateEvaluation::ResourceLimited {
                            stop_search: matches!(&error, RecordError::AllocationFailed),
                        },
                    ));
                }
                return Ok(PartitionEvaluation::Rejected(
                    CandidateEvaluation::Falsified {
                        partition,
                        message_index,
                        error,
                    },
                ));
            }
        }
    }
    Ok(PartitionEvaluation::Complete(ParsedPartition {
        record_count,
        reports,
    }))
}

const fn parser_resource_limit(error: &RecordError) -> bool {
    matches!(
        error,
        RecordError::InputTooLarge { .. }
            | RecordError::TooManyRecords { .. }
            | RecordError::ReportTooLarge { .. }
            | RecordError::AllocationFailed
    )
}

fn parse_input(
    input: &RecordInput<'_>,
    schema: &RecordSchema,
    limits: super::super::RecordLimits,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<RecordParseReport, RecordError> {
    work.as_deref_mut().map_or_else(
        || input.parse(schema, limits),
        |work| input.parse_with_work(schema, limits, work),
    )
}

fn charge_work(work: &mut Option<&mut RecordWorkBudget>, amount: usize) -> bool {
    work.as_deref_mut()
        .is_none_or(|budget| budget.try_charge(amount))
}

fn own_inputs<'bytes>(
    messages: &[&'bytes [u8]],
) -> Result<Vec<RecordInput<'bytes>>, RecordDiscoveryError> {
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(messages.len())
        .map_err(|_| RecordDiscoveryError::RecordOperation(RecordError::AllocationFailed))?;
    inputs.extend(messages.iter().map(|message| RecordInput::new(message)));
    Ok(inputs)
}

fn input_refs<'inputs, 'bytes>(
    inputs: &'inputs [RecordInput<'bytes>],
) -> Result<Vec<&'inputs RecordInput<'bytes>>, RecordDiscoveryError> {
    let mut references = Vec::new();
    references
        .try_reserve_exact(inputs.len())
        .map_err(|_| RecordDiscoveryError::RecordOperation(RecordError::AllocationFailed))?;
    references.extend(inputs.iter());
    Ok(references)
}

fn add_parse_totals(
    report: &RecordParseReport,
    total_record_count: &mut usize,
    total_metadata_bytes: &mut usize,
    limits: super::super::RecordLimits,
) -> Result<usize, RecordDiscoveryError> {
    let message_record_count = report.records().len();
    *total_record_count = total_record_count.checked_add(message_record_count).ok_or(
        RecordDiscoveryError::RecordOperation(RecordError::TooManyRecords {
            count: u64::MAX,
            maximum: limits.max_records,
        }),
    )?;
    if *total_record_count > limits.max_records {
        return Err(RecordDiscoveryError::RecordOperation(
            RecordError::TooManyRecords {
                count: u64::try_from(*total_record_count).unwrap_or(u64::MAX),
                maximum: limits.max_records,
            },
        ));
    }

    for record in report.records() {
        let record_metadata_bytes = std::mem::size_of::<ParsedRecord>()
            .checked_add(record.identifier.len())
            .ok_or(RecordDiscoveryError::RecordOperation(
                RecordError::ReportTooLarge {
                    bytes: usize::MAX,
                    maximum: limits.max_report_bytes,
                },
            ))?;
        *total_metadata_bytes = total_metadata_bytes
            .checked_add(record_metadata_bytes)
            .ok_or(RecordDiscoveryError::RecordOperation(
                RecordError::ReportTooLarge {
                    bytes: usize::MAX,
                    maximum: limits.max_report_bytes,
                },
            ))?;
        if *total_metadata_bytes > limits.max_report_bytes {
            return Err(RecordDiscoveryError::RecordOperation(
                RecordError::ReportTooLarge {
                    bytes: *total_metadata_bytes,
                    maximum: limits.max_report_bytes,
                },
            ));
        }
    }
    Ok(message_record_count)
}

fn record_falsification(
    report: &mut RecordSchemaDiscoveryReport,
    maximum_examples: usize,
    schema: RecordSchema,
    partition: RecordDiscoveryPartition,
    message_index: usize,
    error: RecordError,
    work: &mut Option<&mut RecordWorkBudget>,
) -> Result<bool, RecordDiscoveryError> {
    report.falsified_count = report
        .falsified_count
        .checked_add(1)
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    if report.falsifications.len() >= maximum_examples {
        report.omitted_falsification_examples = report
            .omitted_falsification_examples
            .checked_add(1)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        return Ok(true);
    }
    if !charge_work(work, std::mem::size_of::<RecordSchemaFalsification>()) {
        report.omitted_falsification_examples = report
            .omitted_falsification_examples
            .checked_add(1)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        report.work_limit_reached = true;
        return Ok(false);
    }
    if report.falsifications.try_reserve(1).is_err() {
        report.omitted_falsification_examples = report
            .omitted_falsification_examples
            .checked_add(1)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        return Ok(false);
    }
    report.falsifications.push(RecordSchemaFalsification {
        schema,
        partition,
        message_index,
        error,
    });
    Ok(true)
}
