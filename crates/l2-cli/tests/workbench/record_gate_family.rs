use super::plan::build_schema_plan;
use super::{
    GateStatus, SchemaCandidateOptions, SchemaPlan, SchemaPlanCache, screen_with_schema_plan,
};
use crate::workbench::recovery_executor::relational::DecodedFrameOutput;
use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationPolicy},
    protocol::{
        ByteField, ByteRange, Direction, HoldoutBasis, IntegerField, MessageContext, RecordCount,
        RecordLengthMeaning, RecordLimits, RecordSchema, RecordSchemaProposalLimits,
        RelationalSessionId, RelationalTransformReport, parse_records_with_limits,
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
        work_limited: false,
        has_unassigned_family_messages: false,
        family_search_complete: true,
        assessment_scope: super::SchemaOffsetScope::CompleteInput,
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
fn one_megabyte_record_stream_fits_actual_schema_work_budget() -> TestResult {
    let (frames, plaintext) = large_record_sessions()?;
    assert_eq!(frames.len(), 13);
    let schema = large_record_schema();
    for frame in &frames {
        assert_eq!(frame.preserved_header_end, None);
        assert_eq!(
            frame.payload_range,
            ByteRange {
                start: 0,
                end: frame.bytes.len(),
            }
        );
        assert!(
            parse_records_with_limits(&frame.bytes, &schema, RecordLimits::default())?
                .records()
                .len()
                >= 2
        );
    }
    let report = report_for_partition(7, 6);
    let work_limit = 32 * 1024 * 1024;
    let mut cache = SchemaPlanCache::default();
    let result = cache.screen_candidate(
        &frames,
        &report,
        SchemaCandidateOptions {
            parser_format: ArtifactValidationFormat::Png,
            schema_limits: RecordSchemaProposalLimits::default(),
            artifact_policy: ArtifactValidationPolicy::default(),
            work_limit,
            job: None,
        },
    )?;

    assert!(plaintext.len() >= 1024 * 1024);
    assert_eq!(
        result.status,
        GateStatus::ArtifactValidated,
        "{:?}",
        result.details
    );
    assert!(result.work_bytes <= work_limit);
    let accepted = result
        .accepted_schema
        .as_ref()
        .ok_or("exact PNG validation must retain the accepted record schema")?;
    assert_eq!(
        accepted.artifact_receipt.output_sha256.as_deref(),
        Some(l2_workbench::sha256(&plaintext).as_str())
    );
    Ok(())
}

#[test]
fn exhausted_actual_schema_work_remains_pending_without_a_false_contradiction() -> TestResult {
    let (frames, _) = large_record_sessions()?;
    let report = report_for_partition(7, 6);
    let input_bytes = frames.iter().try_fold(0_usize, |total, frame| {
        total
            .checked_add(frame.bytes.len())
            .ok_or("input length overflowed")
    })?;
    let work_limit = input_bytes.checked_add(1).ok_or("work limit overflowed")?;
    let mut cache = SchemaPlanCache::default();
    let result = cache.screen_candidate(
        &frames,
        &report,
        SchemaCandidateOptions {
            parser_format: ArtifactValidationFormat::Png,
            schema_limits: RecordSchemaProposalLimits::default(),
            artifact_policy: ArtifactValidationPolicy::default(),
            work_limit,
            job: None,
        },
    )?;

    assert_eq!(result.status, GateStatus::Pending, "{:?}", result.details);
    assert!(result.work_bytes <= work_limit);
    assert!(result.work_bytes > 0);
    let alternatives = result
        .details
        .get("schema_alternatives")
        .and_then(Value::as_array)
        .ok_or("work-limited analyses should retain their alternatives")?;
    assert!(
        alternatives.iter().any(|alternative| {
            alternative
                .get("analysis")
                .and_then(|details| details.get("reason"))
                .and_then(Value::as_str)
                == Some("record_schema_work_limit")
        }),
        "expected a work-limit reason in gate alternatives: {:?}",
        result.details
    );
    assert!(
        result
            .details
            .get("schema_search_exhaustive")
            .and_then(Value::as_bool)
            != Some(true)
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
    let png = valid_png()?;
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

fn valid_png() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    let mut encoder = png::Encoder::new(&mut bytes, 1, 1);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.write_header()?.write_image_data(&[10, 20, 30])?;
    Ok(bytes)
}

fn large_record_sessions() -> Result<(Vec<DecodedFrameOutput>, Vec<u8>), Box<dyn Error>> {
    let mut png = valid_png()?;
    let mut text = b"RecoveryFixture\0".to_vec();
    text.resize(1024 * 1024, b'x');
    let iend_start = png.len().checked_sub(12).ok_or("PNG has no IEND chunk")?;
    if png.get(iend_start + 4..iend_start + 8) != Some(b"IEND") {
        return Err("PNG does not end with IEND".into());
    }
    let mut text_chunk = Vec::new();
    append_png_chunk(&mut text_chunk, *b"tEXt", &text)?;
    png.splice(iend_start..iend_start, text_chunk);

    let session_count = 13_usize;
    let chunk_size = 16 * 1024;
    let payloads = png.chunks(chunk_size).collect::<Vec<_>>();
    let records_per_session = payloads.len().div_ceil(session_count);
    let mut frames = Vec::with_capacity(session_count);
    for session_index in 0..session_count {
        let first_record = session_index
            .checked_mul(records_per_session)
            .ok_or("record group offset overflowed")?;
        let mut bytes = Vec::new();
        for record_index in first_record..first_record.saturating_add(records_per_session) {
            let Some(payload) = payloads.get(record_index) else {
                break;
            };
            let sequence = u16::try_from(record_index)?;
            let payload_length = u16::try_from(payload.len())?;
            // One raw decoded suffix contains several complete records
            bytes.extend_from_slice(b"D1");
            bytes.extend_from_slice(&sequence.to_be_bytes());
            bytes.extend_from_slice(&payload_length.to_be_bytes());
            bytes.push(0xa7);
            bytes.extend_from_slice(payload);
        }
        let session = u64::try_from(session_index)?
            .checked_add(1)
            .ok_or("session overflowed")?;
        frames.push(DecodedFrameOutput {
            context: MessageContext {
                source: "large-generated-capture".to_owned(),
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
            parser_format: ArtifactValidationFormat::Png,
            expected_session_orders: vec![0],
            payload_range: ByteRange {
                start: 0,
                end: bytes.len(),
            },
            preserved_header_end: None,
            bytes,
        });
    }
    Ok((frames, png))
}

fn large_record_schema() -> RecordSchema {
    RecordSchema {
        records_offset: 0,
        count: RecordCount::UntilEnd,
        identifier: ByteField {
            offset: 0,
            width: 2,
        },
        sequence: IntegerField {
            offset: 2,
            width: 2,
            byte_order: l2_workbench::protocol::ByteOrder::BigEndian,
        },
        length: IntegerField {
            offset: 4,
            width: 2,
            byte_order: l2_workbench::protocol::ByteOrder::BigEndian,
        },
        data_offset: 7,
        length_meaning: RecordLengthMeaning::PayloadBytes,
        sequence_base: 0,
        terminal_sequence: None,
    }
}

fn report_for_partition(discovery_count: usize, heldout_count: usize) -> RelationalTransformReport {
    let mut report = discovery_report();
    report.discovery_sessions = (1..=u64::try_from(discovery_count).unwrap_or(u64::MAX))
        .map(|session| RelationalSessionId {
            source: "large-generated-capture".to_owned(),
            scope: "all".to_owned(),
            session,
        })
        .collect();
    report.heldout_sessions = (u64::try_from(discovery_count).unwrap_or(u64::MAX) + 1
        ..=u64::try_from(discovery_count.saturating_add(heldout_count)).unwrap_or(u64::MAX))
        .map(|session| RelationalSessionId {
            source: "large-generated-capture".to_owned(),
            scope: "all".to_owned(),
            session,
        })
        .collect();
    report
}

fn append_png_chunk(png: &mut Vec<u8>, kind: [u8; 4], data: &[u8]) -> TestResult {
    png.extend_from_slice(&u32::try_from(data.len())?.to_be_bytes());
    png.extend_from_slice(&kind);
    png.extend_from_slice(data);
    let mut checksum_bytes = kind.to_vec();
    checksum_bytes.extend_from_slice(data);
    png.extend_from_slice(&crc32fast::hash(&checksum_bytes).to_be_bytes());
    Ok(())
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
        prefix_probe_hypotheses_examined: 0,
        prefix_probes_examined: 0,
        prefix_probe_cache_reuses: 0,
        prefix_probe_candidates_with_novelty: 0,
        prefix_probe_work_bytes: 0,
        prefix_probe_complete: true,
        work_bytes: 0,
        work_bytes_remaining: 0,
        search_exhaustive_within_plan: true,
        search_limits: Vec::new(),
        search_limit: None,
    }
}
