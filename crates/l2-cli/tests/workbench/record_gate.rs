use super::{GateResult, GateStatus, SchemaAlternative, SchemaPlan, screen_with_schema_plan};
use crate::workbench::recovery_executor::relational::DecodedFrameOutput;
use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationPolicy},
    protocol::{
        ByteField, ByteOrder, ByteRange, Direction, IntegerField, MessageContext, RecordCount,
        RecordDiscoveryValidationBasis, RecordLengthMeaning, RecordSchema,
        RecordSchemaDiscoveryReport, RecordSchemaHypothesis, RecordSchemaProposalLimits,
    },
};
use serde_json::{Value, json};
use std::error::Error;
use std::sync::Arc;

type TestResult = Result<(), Box<dyn Error>>;

// Corroboration tests need room for parser metadata as well as the tiny input bytes
const STRUCTURAL_CHECK_WORK_LIMIT: usize = 64 * 1024;

#[path = "record_gate_structural_checkpoint.rs"]
mod structural_checkpoint;

#[test]
fn clear_header_frames_without_a_schema_report_remain_pending() -> TestResult {
    let frames = [clear_header_frame()];
    let plan = schema_plan(None, false);
    let result = screen_with_schema_plan(
        &frames,
        ArtifactValidationFormat::Png,
        ArtifactValidationPolicy::default(),
        128,
        None,
        &plan,
        true,
    )?;

    assert_clear_header_pending(&result);
    Ok(())
}

#[test]
fn clear_header_frames_with_no_surviving_schema_remain_pending() -> TestResult {
    let frames = [clear_header_frame()];
    let plan = schema_plan(Some(empty_exhaustive_report()), true);
    let result = screen_with_schema_plan(
        &frames,
        ArtifactValidationFormat::Png,
        ArtifactValidationPolicy::default(),
        128,
        None,
        &plan,
        true,
    )?;

    assert_clear_header_pending(&result);
    Ok(())
}

#[test]
fn constant_size_records_without_sequence_evidence_remain_pending() -> TestResult {
    let frames = [
        structural_frame(1, 0, b"a"),
        structural_frame(2, 0, b"b"),
        structural_frame(3, 0, b"c"),
    ];
    let plan = schema_plan(Some(surviving_report(3)), true);
    let result = screen_with_schema_plan(
        &frames,
        ArtifactValidationFormat::Png,
        ArtifactValidationPolicy::default(),
        STRUCTURAL_CHECK_WORK_LIMIT,
        None,
        &plan,
        false,
    )?;

    assert_eq!(result.status, GateStatus::Pending);
    assert_eq!(
        result.details.get("reason").and_then(Value::as_str),
        Some("record_corroboration_missing"),
        "{:?}",
        result.details
    );
    assert_eq!(
        result.details.get("underdetermined_schemas"),
        Some(&Value::from(1))
    );
    Ok(())
}

#[test]
fn parser_metadata_work_limit_keeps_a_corroborated_schema_pending() -> TestResult {
    let frames = structural_frames();
    let plan = schema_plan(Some(surviving_report(frames.len())), true);
    let work_limit = 1024;
    let result = screen_with_schema_plan(
        &frames,
        ArtifactValidationFormat::Png,
        ArtifactValidationPolicy::default(),
        work_limit,
        None,
        &plan,
        false,
    )?;

    assert_eq!(result.status, GateStatus::Pending);
    assert_eq!(result.work_limited_at, Some(work_limit));
    assert!(result.work_bytes > 0 && result.work_bytes <= work_limit);
    assert!(result.accepted_schema.is_none());
    assert_eq!(result.details.get("schemas_checked"), Some(&Value::from(0)));
    Ok(())
}

#[test]
fn varying_record_lengths_support_a_schema_when_sequences_repeat() -> TestResult {
    let frames = [
        structural_frame_with_length(1, 0, b'A', b"a"),
        structural_frame_with_length(2, 0, b'A', b"bc"),
        structural_frame_with_length(3, 0, b'A', b"def"),
    ];
    let plan = schema_plan(Some(surviving_report(3)), true);
    let result = screen_with_schema_plan(
        &frames,
        ArtifactValidationFormat::Png,
        ArtifactValidationPolicy::default(),
        STRUCTURAL_CHECK_WORK_LIMIT,
        None,
        &plan,
        false,
    )?;

    assert_eq!(
        result.status,
        GateStatus::StructurallySupported,
        "{:?}",
        result.details
    );
    assert!(result.structural_evidence.is_none());
    Ok(())
}

#[test]
fn identical_duplicate_records_keep_contiguous_cross_session_support() -> TestResult {
    let frames = [
        structural_frame(1, 0, b"a"),
        structural_frame(2, 0, b"a"),
        structural_frame(3, 1, b"b"),
        structural_frame(4, 1, b"b"),
    ];
    let plan = schema_plan(Some(surviving_report(4)), true);
    let result = screen_with_schema_plan(
        &frames,
        ArtifactValidationFormat::Png,
        ArtifactValidationPolicy::default(),
        STRUCTURAL_CHECK_WORK_LIMIT,
        None,
        &plan,
        false,
    )?;

    assert_eq!(
        result.status,
        GateStatus::StructurallySupported,
        "{:?}",
        result.details
    );
    Ok(())
}

#[test]
fn contiguous_sequences_support_unknown_terminal_with_optional_family_uncertainty() -> TestResult {
    let frames = structural_frames();
    let plan = uniform_and_pending_family_plan();
    let result = screen_with_schema_plan(
        &frames,
        ArtifactValidationFormat::Png,
        ArtifactValidationPolicy::default(),
        STRUCTURAL_CHECK_WORK_LIMIT,
        None,
        &plan,
        false,
    )?;

    assert_eq!(
        result.status,
        GateStatus::StructurallySupported,
        "{:?}",
        result.details
    );
    assert_eq!(
        result.details.get("family_unassigned_messages"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        result
            .details
            .get("schema_alternatives")
            .and_then(Value::as_array)
            .and_then(|alternatives| alternatives.first())
            .and_then(|alternative| alternative.get("status"))
            .and_then(Value::as_str),
        Some("structurally_supported")
    );
    Ok(())
}

#[test]
fn family_schema_support_stays_pending_when_any_message_is_unassigned() -> TestResult {
    let frames = structural_frames();
    let family_alternative = SchemaAlternative {
        label: "family_selector_0_value_0".to_owned(),
        frame_indices: Some(Arc::from([0_usize, 1])),
        discovery_report: Some(surviving_report(2).into()),
        limits: RecordSchemaProposalLimits::default(),
        discovery_work_bytes: 0,
        learning_message_count: 2,
        heldout_message_count: 0,
        omitted_learning_messages: 0,
        learning_session_count: 2,
        proposal_search_exhaustive: true,
        status: GateStatus::Pending,
        observed: None,
        details: json!({"family":{"unassigned_samples":[3]}}),
    };
    let plan = SchemaPlan {
        alternatives: vec![family_alternative],
        observation_work_bytes: 0,
        details: json!({}),
        work_limited: false,
        has_unassigned_family_messages: true,
        family_search_complete: false,
        assessment_scope: super::SchemaOffsetScope::CompleteInput,
        producer_rule: None,
    };

    let result = screen_with_schema_plan(
        &frames,
        ArtifactValidationFormat::Png,
        ArtifactValidationPolicy::default(),
        STRUCTURAL_CHECK_WORK_LIMIT,
        None,
        &plan,
        false,
    )?;

    assert_eq!(result.status, GateStatus::Pending);
    Ok(())
}

fn assert_clear_header_pending(result: &GateResult) {
    assert_eq!(result.status, GateStatus::Pending);
    assert_eq!(
        result.details.get("reason").and_then(Value::as_str),
        Some("clear_header_schema_only")
    );
    assert_eq!(
        result.details.get("schema_only_constraints"),
        Some(&Value::Bool(true))
    );
}

fn schema_plan(
    discovery_report: Option<RecordSchemaDiscoveryReport>,
    proposal_search_exhaustive: bool,
) -> SchemaPlan {
    let status = if discovery_report.is_some() && proposal_search_exhaustive {
        GateStatus::Contradicted
    } else {
        GateStatus::Pending
    };
    SchemaPlan {
        observation_work_bytes: 0,
        alternatives: vec![SchemaAlternative {
            label: "test".to_owned(),
            frame_indices: None,
            discovery_report: discovery_report.map(Into::into),
            limits: RecordSchemaProposalLimits::default(),
            discovery_work_bytes: 0,
            learning_message_count: 0,
            heldout_message_count: 0,
            omitted_learning_messages: 0,
            learning_session_count: 0,
            proposal_search_exhaustive,
            status,
            observed: None,
            details: json!({"reason":"no_record_schema_candidates"}),
        }],
        work_limited: false,
        details: json!({"reason":"no_record_schema_candidates"}),
        has_unassigned_family_messages: false,
        family_search_complete: true,
        assessment_scope: super::SchemaOffsetScope::CompleteInput,
        producer_rule: None,
    }
}

fn empty_exhaustive_report() -> RecordSchemaDiscoveryReport {
    RecordSchemaDiscoveryReport {
        validation_basis: RecordDiscoveryValidationBasis::HeldOutMessages,
        candidate_combinations: Some(0),
        examined_combinations: 0,
        unexamined_combinations: Some(0),
        search_exhaustive_within_plan: true,
        report_details_complete: true,
        surviving: Vec::new(),
        omitted_survivors: 0,
        falsifications: Vec::new(),
        falsified_count: 0,
        omitted_falsification_examples: 0,
        work_limit_reached: false,
        resource_limited_candidates: 0,
    }
}

fn clear_header_frame() -> DecodedFrameOutput {
    let bytes = vec![0x50, 0x4e, 0x47, 0x00, 1, 2, 3, 4];
    DecodedFrameOutput {
        input_node_id: 1,
        seed_sample: 2,
        context: MessageContext {
            source: "source".to_owned(),
            scope: "scope".to_owned(),
            session: 3,
            direction: Direction::FirstToSecond,
        },
        session_order: 0,
        transformed_output_sha256: l2_workbench::sha256(&bytes),
        direction_node_id: 4,
        episode_node_id: 5,
        stream_offset: 0,
        candidate_index: 0,
        parser_format: ArtifactValidationFormat::Png,
        expected_session_orders: vec![0],
        payload_range: ByteRange { start: 4, end: 8 },
        preserved_header_end: Some(4),
        bytes,
    }
}

fn structural_frames() -> [DecodedFrameOutput; 3] {
    [
        structural_frame(1, 0, b"a"),
        structural_frame(2, 1, b"b"),
        structural_frame(3, 2, b"x"),
    ]
}

fn structural_frame(session: u64, sequence: u8, payload: &[u8]) -> DecodedFrameOutput {
    structural_frame_with_length(session, sequence, b'A', payload)
}

fn structural_frame_with_length(
    session: u64,
    sequence: u8,
    identifier: u8,
    payload: &[u8],
) -> DecodedFrameOutput {
    let payload_length = u8::try_from(payload.len()).unwrap_or(u8::MAX);
    let mut bytes = vec![identifier, sequence, payload_length];
    bytes.extend_from_slice(payload);
    DecodedFrameOutput {
        context: MessageContext {
            source: "source".to_owned(),
            scope: "scope".to_owned(),
            session,
            direction: Direction::FirstToSecond,
        },
        input_node_id: session,
        seed_sample: session,
        session_order: session,
        transformed_output_sha256: l2_workbench::sha256(&bytes),
        direction_node_id: session,
        episode_node_id: session,
        stream_offset: 0,
        candidate_index: 0,
        parser_format: ArtifactValidationFormat::Png,
        expected_session_orders: vec![1, 2, 3],
        payload_range: ByteRange {
            start: 0,
            end: bytes.len(),
        },
        preserved_header_end: None,
        bytes,
    }
}

fn uniform_and_pending_family_plan() -> SchemaPlan {
    SchemaPlan {
        observation_work_bytes: 0,
        alternatives: vec![
            SchemaAlternative {
                label: "uniform:repeated_boundaries".to_owned(),
                frame_indices: None,
                discovery_report: Some(incomplete_surviving_report(3).into()),
                limits: RecordSchemaProposalLimits::default(),
                discovery_work_bytes: 0,
                learning_message_count: 3,
                heldout_message_count: 0,
                omitted_learning_messages: 0,
                learning_session_count: 3,
                proposal_search_exhaustive: false,
                status: GateStatus::Pending,
                observed: None,
                details: json!({"reason":"uniform structural proposal"}),
            },
            SchemaAlternative {
                label: "family_selector_0_value_0".to_owned(),
                frame_indices: Some(Arc::from([0_usize, 1])),
                discovery_report: None,
                limits: RecordSchemaProposalLimits::default(),
                discovery_work_bytes: 0,
                learning_message_count: 2,
                heldout_message_count: 0,
                omitted_learning_messages: 0,
                learning_session_count: 2,
                proposal_search_exhaustive: false,
                status: GateStatus::Pending,
                observed: None,
                details: json!({"family":{"unassigned_samples":[3]}}),
            },
        ],
        work_limited: false,
        details: json!({}),
        has_unassigned_family_messages: true,
        family_search_complete: false,
        assessment_scope: super::SchemaOffsetScope::CompleteInput,
        producer_rule: None,
    }
}

fn surviving_report(training_message_count: usize) -> RecordSchemaDiscoveryReport {
    RecordSchemaDiscoveryReport {
        validation_basis: RecordDiscoveryValidationBasis::TrainingOnly,
        candidate_combinations: Some(1),
        examined_combinations: 1,
        unexamined_combinations: Some(0),
        search_exhaustive_within_plan: true,
        report_details_complete: true,
        surviving: vec![RecordSchemaHypothesis {
            schema: structural_schema(),
            training_message_count,
            held_out_message_count: 0,
            training_record_count: training_message_count,
            held_out_record_count: 0,
        }],
        omitted_survivors: 0,
        falsifications: Vec::new(),
        falsified_count: 0,
        omitted_falsification_examples: 0,
        work_limit_reached: false,
        resource_limited_candidates: 0,
    }
}

fn incomplete_surviving_report(training_message_count: usize) -> RecordSchemaDiscoveryReport {
    let mut report = surviving_report(training_message_count);
    report.candidate_combinations = Some(2);
    report.examined_combinations = 1;
    report.unexamined_combinations = Some(1);
    report.search_exhaustive_within_plan = false;
    report
}

fn structural_schema() -> RecordSchema {
    RecordSchema {
        records_offset: 0,
        count: RecordCount::UntilEnd,
        identifier: ByteField {
            offset: 0,
            width: 1,
        },
        sequence: IntegerField {
            offset: 1,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        length: IntegerField {
            offset: 2,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        data_offset: 3,
        length_meaning: RecordLengthMeaning::PayloadBytes,
        sequence_base: 0,
        terminal_sequence: None,
    }
}
