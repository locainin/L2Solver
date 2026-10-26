use super::plan::build_schema_plan;
use super::{GateStatus, SchemaPlan, screen_with_schema_plan};
use crate::workbench::recovery_executor::relational::DecodedFrameOutput;
use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationPolicy},
    protocol::{
        ByteRange, Direction, HoldoutBasis, MessageContext, RecordSchemaProposalLimits,
        RelationalSessionId, RelationalTransformReport,
    },
};
use serde_json::Value;
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn distinct_training_families_can_recover_one_exact_png_without_cross_merging_schemas() -> TestResult
{
    let frames = mixed_layout_sessions()?;
    let report = discovery_report();
    let plan = build_schema_plan(
        &frames,
        &report,
        RecordSchemaProposalLimits::default(),
        64 * 1024 * 1024,
        ArtifactValidationFormat::Png,
        ArtifactValidationPolicy::default(),
        None,
    )?;

    assert!(
        plan.alternatives
            .iter()
            .any(|alternative| alternative.label.starts_with("family_selector_0_value_"))
    );
    let uniform_only = SchemaPlan {
        alternatives: plan
            .alternatives
            .iter()
            .filter(|alternative| alternative.label.starts_with("uniform:"))
            .cloned()
            .collect(),
        details: Value::Null,
        has_unassigned_family_messages: false,
        family_search_complete: true,
    };
    let uniform_result = screen_with_schema_plan(
        &frames,
        ArtifactValidationFormat::Png,
        ArtifactValidationPolicy::default(),
        64 * 1024 * 1024,
        None,
        &uniform_only,
        false,
    )?;
    assert_ne!(uniform_result.status, GateStatus::ArtifactValidated);

    let result = screen_with_schema_plan(
        &frames,
        ArtifactValidationFormat::Png,
        ArtifactValidationPolicy::default(),
        64 * 1024 * 1024,
        None,
        &plan,
        false,
    )?;

    assert_eq!(result.status, GateStatus::ArtifactValidated);
    assert!(
        result
            .details
            .get("schema_alternatives")
            .and_then(Value::as_array)
            .is_some_and(|alternatives| alternatives.iter().any(|alternative| {
                alternative
                    .get("label")
                    .and_then(Value::as_str)
                    .is_some_and(|label| label.starts_with("family_selector_0_value_"))
                    && alternative.get("status").and_then(Value::as_str)
                        == Some("artifact_validated")
            }))
    );
    Ok(())
}

#[test]
fn unsupported_unique_values_remain_unassigned_and_keep_the_gate_pending() -> TestResult {
    let frames = unique_value_sessions();
    let plan = build_schema_plan(
        &frames,
        &discovery_report(),
        RecordSchemaProposalLimits::default(),
        64 * 1024 * 1024,
        ArtifactValidationFormat::Png,
        ArtifactValidationPolicy::default(),
        None,
    )?;

    assert!(plan.has_unassigned_family_messages);
    assert!(
        plan.alternatives
            .iter()
            .any(|alternative| alternative.label.starts_with("uniform:"))
    );
    assert!(
        plan.alternatives
            .iter()
            .all(|alternative| !alternative.label.starts_with("family_selector_"))
    );

    let result = screen_with_schema_plan(
        &frames,
        ArtifactValidationFormat::Png,
        ArtifactValidationPolicy::default(),
        64 * 1024 * 1024,
        None,
        &plan,
        false,
    )?;
    assert_eq!(result.status, GateStatus::Pending);
    let unsupported = result
        .details
        .get("family_unassigned_sample_details")
        .and_then(Value::as_array)
        .ok_or("unsupported samples should be included in the gate details")?;
    assert_eq!(unsupported.len(), frames.len());
    assert_eq!(
        unsupported
            .first()
            .and_then(|sample| sample.get("context"))
            .and_then(|context| context.get("session"))
            .and_then(Value::as_u64),
        Some(1)
    );
    Ok(())
}

fn mixed_layout_sessions() -> Result<Vec<DecodedFrameOutput>, Box<dyn Error>> {
    let png = valid_png();
    let (first_chunk, second_chunk) = png
        .split_at_checked(23)
        .ok_or("PNG fixture is shorter than the configured family split")?;
    let chunks: [&[u8]; 2] = (first_chunk, second_chunk).into();
    let mut frames = Vec::new();
    for (session_id, (family, header_length)) in [
        (1_u64, (b'A', 4_usize)),
        (2, (b'A', 4)),
        (3, (b'B', 5)),
        (4, (b'B', 5)),
    ] {
        for (sequence, payload) in chunks.iter().enumerate() {
            let frame_bytes = encode_record(
                family,
                u8::try_from(session_id).unwrap_or(u8::MAX),
                u8::try_from(sequence).unwrap_or(u8::MAX),
                payload,
            );
            let sequence_id = u64::try_from(sequence).unwrap_or(u64::MAX);
            let sample_id = session_id
                .saturating_mul(10)
                .saturating_add(sequence_id.saturating_add(1));
            frames.push(DecodedFrameOutput {
                context: MessageContext {
                    source: "capture-sha256".to_owned(),
                    scope: "all".to_owned(),
                    session: session_id,
                    direction: Direction::FirstToSecond,
                },
                input_node_id: sample_id,
                seed_sample: sample_id,
                session_order: 0,
                transformed_output_sha256: l2_workbench::sha256(&frame_bytes),
                direction_node_id: 100 + session_id,
                episode_node_id: 200 + session_id,
                stream_offset: sequence.saturating_mul(32),
                candidate_index: 0,
                parser_format: ArtifactValidationFormat::Png,
                expected_session_orders: vec![0],
                payload_range: ByteRange {
                    start: header_length,
                    end: frame_bytes.len(),
                },
                preserved_header_end: Some(header_length),
                bytes: frame_bytes,
            });
        }
    }
    Ok(frames)
}

fn unique_value_sessions() -> Vec<DecodedFrameOutput> {
    (1..=4_u64)
        .map(|session_id| {
            let bytes = vec![u8::try_from(session_id).unwrap_or(u8::MAX); 24];
            DecodedFrameOutput {
                context: MessageContext {
                    source: "capture-sha256".to_owned(),
                    scope: "all".to_owned(),
                    session: session_id,
                    direction: Direction::FirstToSecond,
                },
                input_node_id: session_id,
                seed_sample: session_id,
                session_order: 0,
                transformed_output_sha256: l2_workbench::sha256(&bytes),
                direction_node_id: 100 + session_id,
                episode_node_id: 200 + session_id,
                stream_offset: 0,
                candidate_index: 0,
                parser_format: ArtifactValidationFormat::Png,
                expected_session_orders: vec![0],
                payload_range: ByteRange {
                    start: 0,
                    end: bytes.len(),
                },
                preserved_header_end: None,
                bytes,
            }
        })
        .collect()
}

fn encode_record(family: u8, object_id: u8, sequence: u8, payload: &[u8]) -> Vec<u8> {
    let mut record = vec![family];
    if family == b'B' {
        record.push(b'X');
    }
    record.push(object_id);
    record.push(sequence);
    record.push(u8::try_from(payload.len()).unwrap_or(u8::MAX));
    record.extend_from_slice(payload);
    record
}

fn valid_png() -> Vec<u8> {
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut header = Vec::new();
    header.extend_from_slice(&1_u32.to_be_bytes());
    header.extend_from_slice(&1_u32.to_be_bytes());
    header.extend_from_slice(&[8, 2, 0, 0, 0]);
    append_png_chunk(&mut png, *b"IHDR", &header);
    append_png_chunk(&mut png, *b"IEND", &[]);
    png
}

fn append_png_chunk(png: &mut Vec<u8>, kind: [u8; 4], data: &[u8]) {
    png.extend_from_slice(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_be_bytes());
    png.extend_from_slice(&kind);
    png.extend_from_slice(data);
    let mut checksum_bytes = kind.to_vec();
    checksum_bytes.extend_from_slice(data);
    png.extend_from_slice(&crc32fast::hash(&checksum_bytes).to_be_bytes());
}

fn discovery_report() -> RelationalTransformReport {
    RelationalTransformReport {
        split_basis: HoldoutBasis::CompleteSessions,
        discovery_sessions: (1..=4)
            .map(|session| RelationalSessionId {
                source: "capture-sha256".to_owned(),
                scope: "all".to_owned(),
                session,
            })
            .collect(),
        heldout_sessions: Vec::new(),
        candidates: Vec::new(),
        equivalent_candidate_aliases: 0,
        candidates_examined: 1,
        omitted_candidates: 0,
        omitted_candidates_exact: true,
        candidate_limit_remaining: 0,
        locator_candidates_examined: 1,
        locator_candidate_limit_remaining: 0,
        work_bytes: 0,
        work_bytes_remaining: 0,
        search_exhaustive_within_plan: true,
        search_limits: Vec::new(),
        search_limit: None,
    }
}
