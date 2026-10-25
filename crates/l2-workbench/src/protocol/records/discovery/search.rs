use super::super::{
    ParsedRecord, RecordError, RecordParseReport, RecordSchema, parse_records_with_limits,
};
use super::error::RecordDiscoveryError;
use super::model::{
    RecordDiscoveryLimits, RecordDiscoveryPartition, RecordDiscoveryValidationBasis,
    RecordSchemaDiscoveryReport, RecordSchemaDiscoverySpace, RecordSchemaFalsification,
    RecordSchemaHypothesis, seen_candidate,
};
use std::collections::HashSet;

/// Discover exact record layouts from caller-framed training and held-out messages
///
/// Each candidate describes a complete repeated-record list using caller-selected offsets and
/// count modes. The strict parser must consume every message. Discovery reports only parse
/// counts; assembly remains separate because these inputs have no capture or conversation context
/// Empty holdout input selects training-only validation, which the report identifies explicitly
///
/// # Errors
/// Rejects empty domains, insufficient messages, invalid limits, and aggregate resource excess
pub fn discover_record_schemas(
    training_messages: &[&[u8]],
    held_out_messages: &[&[u8]],
    space: &RecordSchemaDiscoverySpace,
    limits: RecordDiscoveryLimits,
) -> Result<RecordSchemaDiscoveryReport, RecordDiscoveryError> {
    space.validate()?;
    discover_record_schemas_from_candidates(
        training_messages,
        held_out_messages,
        space.candidate_count(),
        limits,
        |ordinal| space.candidate_at(ordinal),
    )
}

pub(in crate::protocol::records) fn discover_record_schemas_from_candidates<F>(
    training_messages: &[&[u8]],
    held_out_messages: &[&[u8]],
    candidate_combinations: Option<usize>,
    limits: RecordDiscoveryLimits,
    candidate_at: F,
) -> Result<RecordSchemaDiscoveryReport, RecordDiscoveryError>
where
    F: FnMut(usize) -> Option<RecordSchema>,
{
    limits.validate()?;
    validate_messages(training_messages, held_out_messages, limits)?;

    let validation_basis = if held_out_messages.is_empty() {
        RecordDiscoveryValidationBasis::TrainingOnly
    } else {
        RecordDiscoveryValidationBasis::HeldOutMessages
    };
    let mut report = discovery_report(candidate_combinations, validation_basis);
    evaluate_combinations(
        &mut report,
        training_messages,
        held_out_messages,
        limits,
        candidate_combinations,
        candidate_at,
    )?;
    report.unexamined_combinations = candidate_combinations
        .map(|total| {
            total
                .checked_sub(report.examined_combinations)
                .ok_or(RecordDiscoveryError::InvalidLimits)
        })
        .transpose()?;
    report.search_exhaustive_within_plan = report.unexamined_combinations == Some(0);
    report.report_details_complete =
        report.omitted_survivors == 0 && report.omitted_falsification_examples == 0;
    Ok(report)
}

fn validate_messages(
    training_messages: &[&[u8]],
    held_out_messages: &[&[u8]],
    limits: RecordDiscoveryLimits,
) -> Result<(), RecordDiscoveryError> {
    // Training needs multiple examples; held-out evidence is optional
    if training_messages.len() < 2 {
        return Err(RecordDiscoveryError::InsufficientMessages {
            training: training_messages.len(),
            held_out: held_out_messages.len(),
        });
    }

    let message_count = training_messages
        .len()
        .checked_add(held_out_messages.len())
        .ok_or(RecordDiscoveryError::TooManyMessages {
            count: usize::MAX,
            maximum: limits.max_messages,
        })?;
    if message_count > limits.max_messages {
        return Err(RecordDiscoveryError::TooManyMessages {
            count: message_count,
            maximum: limits.max_messages,
        });
    }
    if message_count > limits.record_limits.max_records {
        return Err(RecordDiscoveryError::RecordOperation(
            RecordError::TooManyRecords {
                count: u64::try_from(message_count).map_or(u64::MAX, std::convert::identity),
                maximum: limits.record_limits.max_records,
            },
        ));
    }

    // One shared input ceiling applies across both message partitions
    let mut total_input_bytes = 0_usize;
    for message in training_messages.iter().chain(held_out_messages) {
        total_input_bytes = total_input_bytes.checked_add(message.len()).ok_or(
            RecordDiscoveryError::RecordOperation(RecordError::InputTooLarge {
                length: usize::MAX,
                maximum: limits.record_limits.max_input_bytes,
            }),
        )?;
    }
    if total_input_bytes > limits.record_limits.max_input_bytes {
        return Err(RecordDiscoveryError::RecordOperation(
            RecordError::InputTooLarge {
                length: total_input_bytes,
                maximum: limits.record_limits.max_input_bytes,
            },
        ));
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
        surviving: Vec::new(),
        omitted_survivors: 0,
        falsifications: Vec::new(),
        falsified_count: 0,
        omitted_falsification_examples: 0,
    }
}

fn evaluate_combinations<F>(
    report: &mut RecordSchemaDiscoveryReport,
    training_messages: &[&[u8]],
    held_out_messages: &[&[u8]],
    limits: RecordDiscoveryLimits,
    candidate_combinations: Option<usize>,
    mut candidate_at: F,
) -> Result<(), RecordDiscoveryError>
where
    F: FnMut(usize) -> Option<RecordSchema>,
{
    let combination_budget = candidate_combinations
        .unwrap_or(limits.max_candidates)
        .min(limits.max_candidates);
    let mut seen = HashSet::new();

    for ordinal in 0..combination_budget {
        let schema = candidate_at(ordinal).ok_or(RecordDiscoveryError::InvalidLimits)?;
        report.examined_combinations = report
            .examined_combinations
            .checked_add(1)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        // Repeated entries in caller domains describe the same schema only once
        if !seen_candidate(&mut seen, &schema)? {
            continue;
        }
        match evaluate_candidate(
            &schema,
            training_messages,
            held_out_messages,
            limits.record_limits,
        )? {
            CandidateEvaluation::Falsified {
                partition,
                message_index,
                error,
            } => record_falsification(
                report,
                limits.max_falsifications,
                schema,
                partition,
                message_index,
                error,
            )?,
            CandidateEvaluation::Survives {
                training_record_count,
                held_out_record_count,
            } => {
                if report.surviving.len() >= limits.max_survivors {
                    report.omitted_survivors = report
                        .omitted_survivors
                        .checked_add(1)
                        .ok_or(RecordDiscoveryError::InvalidLimits)?;
                    continue;
                }
                report.surviving.try_reserve(1).map_err(|_| {
                    RecordDiscoveryError::RecordOperation(RecordError::AllocationFailed)
                })?;
                report.surviving.push(RecordSchemaHypothesis {
                    schema,
                    training_message_count: training_messages.len(),
                    held_out_message_count: held_out_messages.len(),
                    training_record_count,
                    held_out_record_count,
                });
            }
        }
    }
    Ok(())
}

enum CandidateEvaluation {
    Falsified {
        partition: RecordDiscoveryPartition,
        message_index: usize,
        error: RecordError,
    },
    Survives {
        training_record_count: usize,
        held_out_record_count: usize,
    },
}

fn evaluate_candidate(
    schema: &RecordSchema,
    training_messages: &[&[u8]],
    held_out_messages: &[&[u8]],
    record_limits: super::super::RecordLimits,
) -> Result<CandidateEvaluation, RecordDiscoveryError> {
    let mut total_record_count = 0_usize;
    let mut total_metadata_bytes = 0_usize;
    let mut training_record_count = 0_usize;
    for (message_index, bytes) in training_messages.iter().enumerate() {
        match parse_records_with_limits(bytes, schema, record_limits) {
            Ok(report) => {
                let count = add_parse_totals(
                    &report,
                    &mut total_record_count,
                    &mut total_metadata_bytes,
                    record_limits,
                )?;
                training_record_count = training_record_count
                    .checked_add(count)
                    .ok_or(RecordDiscoveryError::InvalidLimits)?;
            }
            Err(error) => {
                return Ok(CandidateEvaluation::Falsified {
                    partition: RecordDiscoveryPartition::Training,
                    message_index,
                    error,
                });
            }
        }
    }
    let mut held_out_record_count = 0_usize;
    for (message_index, bytes) in held_out_messages.iter().enumerate() {
        match parse_records_with_limits(bytes, schema, record_limits) {
            Ok(report) => {
                let count = add_parse_totals(
                    &report,
                    &mut total_record_count,
                    &mut total_metadata_bytes,
                    record_limits,
                )?;
                held_out_record_count = held_out_record_count
                    .checked_add(count)
                    .ok_or(RecordDiscoveryError::InvalidLimits)?;
            }
            Err(error) => {
                return Ok(CandidateEvaluation::Falsified {
                    partition: RecordDiscoveryPartition::HeldOut,
                    message_index,
                    error,
                });
            }
        }
    }
    Ok(CandidateEvaluation::Survives {
        training_record_count,
        held_out_record_count,
    })
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
) -> Result<(), RecordDiscoveryError> {
    report.falsified_count = report
        .falsified_count
        .checked_add(1)
        .ok_or(RecordDiscoveryError::InvalidLimits)?;
    if report.falsifications.len() >= maximum_examples {
        report.omitted_falsification_examples = report
            .omitted_falsification_examples
            .checked_add(1)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        return Ok(());
    }
    report
        .falsifications
        .try_reserve(1)
        .map_err(|_| RecordDiscoveryError::RecordOperation(RecordError::AllocationFailed))?;
    report.falsifications.push(RecordSchemaFalsification {
        schema,
        partition,
        message_index,
        error,
    });
    Ok(())
}
