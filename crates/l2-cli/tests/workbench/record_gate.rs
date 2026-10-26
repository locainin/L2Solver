use super::{GateResult, GateStatus, SchemaPlan, screen_with_schema_plan};
use crate::workbench::recovery_executor::relational::DecodedFrameOutput;
use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationPolicy},
    protocol::{
        ByteRange, Direction, MessageContext, RecordDiscoveryValidationBasis,
        RecordSchemaDiscoveryReport, RecordSchemaProposalLimits,
    },
};
use serde_json::{Value, json};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

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
    SchemaPlan {
        discovery_report,
        limits: RecordSchemaProposalLimits::default(),
        discovery_work_bytes: 0,
        learning_message_count: 0,
        heldout_message_count: 0,
        omitted_learning_messages: 0,
        learning_session_count: 0,
        proposal_search_exhaustive,
        status: GateStatus::Contradicted,
        details: json!({"reason":"no_record_schema_candidates"}),
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
    }
}

fn clear_header_frame() -> DecodedFrameOutput {
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
        direction_node_id: 4,
        episode_node_id: 5,
        stream_offset: 0,
        candidate_index: 0,
        parser_format: ArtifactValidationFormat::Png,
        expected_session_orders: vec![0],
        payload_range: ByteRange { start: 4, end: 8 },
        preserved_header_end: Some(4),
        bytes: vec![0x50, 0x4e, 0x47, 0x00, 1, 2, 3, 4],
    }
}
