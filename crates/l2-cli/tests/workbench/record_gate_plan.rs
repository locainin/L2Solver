use super::super::prepare_schema_limits;
use super::{AnalysisRequest, LearningMessages, analysis_details};
use crate::workbench::recovery_executor::relational::DecodedFrameOutput;
use crate::workbench::recovery_executor::relational::record_gate::GateStatus;
use l2_workbench::protocol::{
    ByteRange, Direction, MessageContext, RecordBoundaryCue, RecordDiscoveryValidationBasis,
    RecordSchemaAnalysisReport, RecordSchemaDiscoveryReport, RecordSchemaProposalLimits,
    RecordSchemaProposalReport, RecordSchemaProposalValidationBasis,
};
use serde_json::Value;
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn analysis_details_retain_omitted_views_and_training_boundary_cues() {
    let proposal = proposal();
    let discovery = empty_report();
    let analysis = RecordSchemaAnalysisReport {
        proposal,
        discovery: Some(discovery),
    };
    let messages = LearningMessages {
        training: vec![&[]],
        heldout: Vec::new(),
        training_indices: Vec::new(),
        heldout_indices: Vec::new(),
        all_training_indices: Vec::new(),
        all_heldout_indices: Vec::new(),
        training_data_offsets: Vec::new(),
        learning_bytes: 0,
        analysis_input_bytes: 0,
        eligible_input_bytes: 0,
        full_input_bytes: 0,
        training_session_count: 2,
    };
    let request = AnalysisRequest {
        label: "test",
        family_details: None,
        frame_indices: None,
        messages: &messages,
        limits: RecordSchemaProposalLimits::default(),
        work_limit: 128,
        analysis_work_limit: 128,
        observer_work_limit: 0,
        observer: None,
        omitted_learning_messages: 0,
        job: None,
    };
    let details = analysis_details(&analysis, &request, GateStatus::Pending, 0, 0);

    assert_eq!(details.get("omitted_record_views"), Some(&Value::from(7)));
    assert_eq!(
        details
            .get("repeated_boundary_cues")
            .and_then(Value::as_array)
            .and_then(|cues| cues.first())
            .and_then(|cue| cue.get("message_index")),
        Some(&Value::from(1))
    );
}

#[test]
fn training_boundary_at_offset_sixteen_is_admitted_without_using_another_frame() -> TestResult {
    let frames = [frame(1, Some(16)), frame(2, Some(3))];
    let messages = LearningMessages {
        training: vec![frames[0].bytes.as_slice()],
        heldout: Vec::new(),
        training_indices: vec![0],
        heldout_indices: Vec::new(),
        all_training_indices: vec![0],
        all_heldout_indices: Vec::new(),
        training_data_offsets: vec![16],
        learning_bytes: frames[0].bytes.len(),
        analysis_input_bytes: frames[0].bytes.len(),
        eligible_input_bytes: frames[0].bytes.len(),
        full_input_bytes: frames.iter().map(|item| item.bytes.len()).sum(),
        training_session_count: 1,
    };

    let limits = prepare_schema_limits(
        RecordSchemaProposalLimits::default(),
        &frames,
        &[0],
        &messages,
        64 * 1024,
    )?
    .ok_or("the input budget should permit analysis")?;

    assert_eq!(limits.max_field_offset, 16);
    Ok(())
}

#[test]
fn empty_preserved_prefix_does_not_cap_inferred_fields_at_zero() -> TestResult {
    let frames = [frame(1, Some(0))];
    let messages = LearningMessages {
        training: vec![frames[0].bytes.as_slice()],
        heldout: Vec::new(),
        training_indices: vec![0],
        heldout_indices: Vec::new(),
        all_training_indices: vec![0],
        all_heldout_indices: Vec::new(),
        training_data_offsets: Vec::new(),
        learning_bytes: frames[0].bytes.len(),
        analysis_input_bytes: frames[0].bytes.len(),
        eligible_input_bytes: frames[0].bytes.len(),
        full_input_bytes: frames[0].bytes.len(),
        training_session_count: 1,
    };

    let limits = prepare_schema_limits(
        RecordSchemaProposalLimits::default(),
        &frames,
        &[0],
        &messages,
        64 * 1024,
    )?
    .ok_or("the input budget should permit analysis")?;

    assert_eq!(limits.max_field_offset, 15);
    Ok(())
}

#[test]
fn parser_limits_cover_full_eligible_frames_after_sampled_learning() -> TestResult {
    let frames = [frame(1, None), frame(2, None)];
    let selected_bytes = frames[0].bytes.len();
    let eligible_bytes = frames.iter().map(|item| item.bytes.len()).sum::<usize>();
    let messages = LearningMessages {
        training: vec![frames[0].bytes.as_slice()],
        heldout: Vec::new(),
        training_indices: vec![0],
        heldout_indices: Vec::new(),
        all_training_indices: vec![0, 1],
        all_heldout_indices: Vec::new(),
        training_data_offsets: Vec::new(),
        learning_bytes: selected_bytes,
        analysis_input_bytes: selected_bytes,
        eligible_input_bytes: eligible_bytes,
        full_input_bytes: eligible_bytes,
        training_session_count: 1,
    };

    let limits = prepare_schema_limits(
        RecordSchemaProposalLimits::default(),
        &frames,
        &[0],
        &messages,
        64 * 1024,
    )?
    .ok_or("the sampled search budget should permit analysis")?;

    assert_eq!(
        limits.discovery.record_limits.max_input_bytes,
        eligible_bytes
    );
    assert_eq!(
        limits.discovery.record_limits.max_output_bytes,
        eligible_bytes
    );
    Ok(())
}

fn frame(session: u64, preserved_header_end: Option<usize>) -> DecodedFrameOutput {
    let bytes = vec![0; 17];
    DecodedFrameOutput {
        context: MessageContext {
            source: "source".to_owned(),
            scope: "all".to_owned(),
            session,
            direction: Direction::FirstToSecond,
        },
        input_node_id: session,
        seed_sample: session,
        session_order: 0,
        transformed_output_sha256: l2_workbench::sha256(&bytes),
        direction_node_id: session,
        episode_node_id: session,
        stream_offset: 0,
        candidate_index: 0,
        parser_format: l2_workbench::artifact::ArtifactValidationFormat::Png,
        expected_session_orders: vec![0],
        payload_range: ByteRange { start: 0, end: 1 },
        preserved_header_end,
        bytes,
    }
}

fn proposal() -> RecordSchemaProposalReport {
    RecordSchemaProposalReport {
        validation_basis: RecordSchemaProposalValidationBasis::DiscoveryOnly,
        training_message_count: 1,
        held_out_message_count: 0,
        candidate_space: None,
        candidate_combinations: Some(0),
        examined_field_checks: 0,
        omitted_field_checks: 0,
        examined_pair_checks: 0,
        omitted_pair_checks: 0,
        examined_length_checks: 0,
        omitted_length_checks: 0,
        omitted_record_views: 7,
        repeated_boundary_cues: vec![RecordBoundaryCue {
            message_index: 1,
            range: l2_workbench::protocol::ByteRange { start: 3, end: 5 },
        }],
        omitted_schema_combinations: Some(0),
        search_exhaustive_within_plan: false,
        limitations: ["test", "test"],
    }
}

fn empty_report() -> RecordSchemaDiscoveryReport {
    RecordSchemaDiscoveryReport {
        validation_basis: RecordDiscoveryValidationBasis::TrainingOnly,
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
