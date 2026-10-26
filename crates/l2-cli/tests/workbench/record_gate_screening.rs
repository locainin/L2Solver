use super::plan::build_schema_plan;
use super::screen::{
    SchemaAlternativeEvaluation, SchemaScreenContext, SurvivingSchemaInputs,
    observe_surviving_schema,
};
use super::{GateStatus, SchemaCandidateOptions, SchemaPlanCache, screen_with_schema_plan};
use crate::workbench::recovery_executor::relational::DecodedFrameOutput;
use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationPolicy, PNG_SIGNATURE},
    protocol::{
        ByteRange, Direction, HoldoutBasis, MessageContext, RecordDiscoveryLimits,
        RecordParseReport, RecordSchemaProposalLimits, RelationalSessionId,
        RelationalTransformReport,
    },
};
use serde_json::Value;
use std::error::Error;

type TestResult<T> = Result<T, Box<dyn Error>>;

#[test]
fn one_input_with_multiple_records_reaches_schema_discovery() -> TestResult<()> {
    let (signature_prefix, signature_suffix) = PNG_SIGNATURE
        .split_at_checked(4)
        .ok_or("PNG signature is shorter than the fixture split")?;
    let mut records = length_prefixed_record(signature_prefix)?;
    records.extend_from_slice(&length_prefixed_record(signature_suffix)?);
    let mut frame = source_framed_frame(&records);
    frame.context.session = 1;
    let frames = [frame];
    let mut cache = SchemaPlanCache::default();

    let result = cache.screen_candidate(
        &frames,
        &report_with_sessions(&[1], &[]),
        candidate_options(
            ArtifactValidationFormat::Png,
            RecordSchemaProposalLimits::default(),
            ArtifactValidationPolicy::default(),
            1024 * 1024,
        ),
    )?;

    assert_eq!(cache.plans.len(), 1);
    assert_eq!(
        result
            .details
            .get("schema_plan_cache_hit")
            .and_then(Value::as_bool),
        Some(false)
    );
    Ok(())
}

#[test]
fn multiple_inputs_with_record_fragments_reach_schema_discovery() -> TestResult<()> {
    let (signature_prefix, signature_suffix) = PNG_SIGNATURE
        .split_at_checked(4)
        .ok_or("PNG signature is shorter than the fixture split")?;
    let first_record = length_prefixed_record(signature_prefix)?;
    let second_record = length_prefixed_record(signature_suffix)?;
    let mut first = source_framed_frame(&first_record);
    first.input_node_id = 1;
    first.context.session = 1;
    let mut second = source_framed_frame(&second_record);
    second.input_node_id = 2;
    second.context.session = 2;
    let frames = [first, second];
    let mut cache = SchemaPlanCache::default();

    let result = cache.screen_candidate(
        &frames,
        &report_with_sessions(&[1], &[2]),
        candidate_options(
            ArtifactValidationFormat::Png,
            RecordSchemaProposalLimits::default(),
            ArtifactValidationPolicy::default(),
            1024 * 1024,
        ),
    )?;

    assert_eq!(cache.plans.len(), 1);
    assert_eq!(
        result
            .details
            .get("schema_plan_cache_hit")
            .and_then(Value::as_bool),
        Some(false)
    );
    Ok(())
}

#[test]
fn preserved_header_bytes_still_reach_schema_discovery() -> TestResult<()> {
    let mut frame = source_framed_frame(b"HEADGET /index.html HTTP/1.1\r\n");
    frame.context.session = 1;
    frame.preserved_header_end = Some(4);
    frame.payload_range = ByteRange {
        start: 4,
        end: frame.bytes.len(),
    };
    let frames = [frame];
    let mut cache = SchemaPlanCache::default();
    let result = cache.screen_candidate(
        &frames,
        &report_with_sessions(&[1], &[]),
        candidate_options(
            ArtifactValidationFormat::Png,
            RecordSchemaProposalLimits::default(),
            ArtifactValidationPolicy::default(),
            1024 * 1024,
        ),
    )?;

    assert_eq!(cache.plans.len(), 1);
    assert_eq!(
        result.details.get("reason").and_then(Value::as_str),
        Some("clear_header_schema_only")
    );
    Ok(())
}

#[test]
fn empty_preserved_prefix_does_not_force_clear_header_only_pending() -> TestResult<()> {
    let frame = source_framed_frame(b"HEADGET /index.html HTTP/1.1\r\n");
    let frames = [frame];
    let mut cache = SchemaPlanCache::default();

    let result = cache.screen_candidate(
        &frames,
        &report_with_sessions(&[1], &[]),
        candidate_options(
            ArtifactValidationFormat::Png,
            RecordSchemaProposalLimits::default(),
            ArtifactValidationPolicy::default(),
            1024 * 1024,
        ),
    )?;

    assert_ne!(
        result.details.get("reason").and_then(Value::as_str),
        Some("clear_header_schema_only")
    );
    Ok(())
}

#[test]
fn schema_discovery_returns_pending_when_its_work_budget_is_too_small() -> TestResult<()> {
    let frame = source_framed_frame(&[b'x'; 128]);
    let frames = [frame];
    let mut cache = SchemaPlanCache::default();
    let result = cache.screen_candidate(
        &frames,
        &report_with_sessions(&[1], &[]),
        candidate_options(
            ArtifactValidationFormat::Png,
            RecordSchemaProposalLimits::default(),
            ArtifactValidationPolicy::default(),
            16,
        ),
    )?;

    assert_eq!(result.status, GateStatus::Pending);
    assert!(result.work_bytes <= 16);
    assert_eq!(cache.plans.len(), 1);
    Ok(())
}

#[test]
fn changed_transformed_bytes_with_the_same_layout_do_not_reuse_a_schema_plan() -> TestResult<()> {
    let first = [clear_header_frame(b"first value")];
    let second = [clear_header_frame(b"other value")];
    let mut cache = SchemaPlanCache::default();
    let _first_result = cache.screen_candidate(
        &first,
        &report_with_sessions(&[1], &[]),
        candidate_options(
            ArtifactValidationFormat::Png,
            RecordSchemaProposalLimits::default(),
            ArtifactValidationPolicy::default(),
            1024 * 1024,
        ),
    )?;
    let second_result = cache.screen_candidate(
        &second,
        &report_with_sessions(&[1], &[]),
        candidate_options(
            ArtifactValidationFormat::Png,
            RecordSchemaProposalLimits::default(),
            ArtifactValidationPolicy::default(),
            1024 * 1024,
        ),
    )?;

    assert_eq!(
        second_result
            .details
            .get("schema_plan_cache_hit")
            .and_then(Value::as_bool),
        Some(false)
    );
    Ok(())
}

#[test]
fn schema_plan_cache_scopes_format_policy_limits_and_work_budget() -> TestResult<()> {
    let frames = [clear_header_frame(b"same layout")];
    let report = report_with_sessions(&[1], &[]);
    let default_policy = ArtifactValidationPolicy::default();
    let default_limits = RecordSchemaProposalLimits::default();
    let default_work = 1024_usize * 1024;
    let mut changed_limits = default_limits;
    changed_limits.max_field_offset = changed_limits.max_field_offset.saturating_sub(1);
    let changed_policy = ArtifactValidationPolicy {
        max_input_bytes: default_policy.max_input_bytes.saturating_sub(1),
        ..default_policy
    };
    let variants = [
        (
            ArtifactValidationFormat::Zip,
            default_policy,
            default_limits,
            default_work,
        ),
        (
            ArtifactValidationFormat::Png,
            changed_policy,
            default_limits,
            default_work,
        ),
        (
            ArtifactValidationFormat::Png,
            default_policy,
            changed_limits,
            default_work,
        ),
        (
            ArtifactValidationFormat::Png,
            default_policy,
            default_limits,
            default_work.saturating_add(1),
        ),
    ];

    for (format, policy, limits, work_limit) in variants {
        let mut cache = SchemaPlanCache::default();
        let _initial = cache.screen_candidate(
            &frames,
            &report,
            candidate_options(
                ArtifactValidationFormat::Png,
                default_limits,
                default_policy,
                default_work,
            ),
        )?;
        let changed = cache.screen_candidate(
            &frames,
            &report,
            candidate_options(format, limits, policy, work_limit),
        )?;

        assert_eq!(
            changed
                .details
                .get("schema_plan_cache_hit")
                .and_then(Value::as_bool),
            Some(false)
        );
    }
    Ok(())
}

#[test]
fn exact_artifact_validation_uses_a_survivor_omitted_from_report_details() -> TestResult<()> {
    let fixture = crate::workbench::recovery_executor::record_discovery_tests::
        build_session_relative_fixture()?;
    let frames = source_framed_png_frames(&fixture.plaintext)?;
    let work_limit = 64 * 1024 * 1024;
    let default_limits = RecordSchemaProposalLimits::default();
    let limits = RecordSchemaProposalLimits {
        discovery: RecordDiscoveryLimits {
            max_survivors: 2,
            ..default_limits.discovery
        },
        max_field_offset: 10,
        ..default_limits
    };

    let plan = build_schema_plan(
        &frames,
        &report_with_sessions(&[1, 2], &[3, 4]),
        limits,
        work_limit,
        ArtifactValidationFormat::Png,
        ArtifactValidationPolicy::default(),
        None,
    )?;
    let artifact_alternative = plan
        .alternatives
        .iter()
        .find(|alternative| {
            alternative
                .observed
                .as_ref()
                .is_some_and(|observed| observed.exact_artifact_matches > 0)
        })
        .ok_or("an observed schema should validate the reconstructed PNG")?;
    let report = artifact_alternative
        .discovery_report
        .as_ref()
        .ok_or("the artifact schema discovery report is missing")?;
    let observed = artifact_alternative
        .observed
        .as_ref()
        .ok_or("the artifact schema observer summary is missing")?;
    let exact_ordinal = observed
        .exact_artifact_survivor_ordinal
        .ok_or("the artifact validating survivor ordinal is missing")?;
    assert!(
        exact_ordinal > report.surviving.len(),
        "exact artifact schema must be omitted from bounded detail retention: ordinal={exact_ordinal}, retained={}, label={}",
        report.surviving.len(),
        artifact_alternative.label
    );
    assert!(report.omitted_survivors > 0);

    let gate = screen_with_schema_plan(
        &frames,
        ArtifactValidationFormat::Png,
        ArtifactValidationPolicy::default(),
        work_limit,
        None,
        &plan,
        false,
    )?;

    assert_eq!(gate.status, GateStatus::ArtifactValidated);
    assert!(gate.work_bytes <= work_limit);
    let details = gate
        .details
        .get("schema_alternatives")
        .and_then(Value::as_array)
        .ok_or("schema alternative details are missing")?;
    assert!(details.iter().any(|alternative| {
        alternative
            .get("artifact_validating_survivor_ordinal")
            .and_then(Value::as_u64)
            .is_some_and(|ordinal| ordinal > report.surviving.len() as u64)
            && alternative
                .get("omitted_schema_survivors")
                .and_then(Value::as_u64)
                .is_some_and(|omitted| omitted > 0)
    }));
    Ok(())
}

#[test]
fn exact_artifact_validation_applies_surviving_schema_to_omitted_eligible_frames() -> TestResult<()>
{
    let fixture = crate::workbench::recovery_executor::record_discovery_tests::
        build_session_relative_fixture()?;
    let source_frames = source_framed_png_frames(&fixture.plaintext)?;
    let mut remaining = source_frames.into_iter().map(Some).collect::<Vec<_>>();
    let mut frames = Vec::new();
    for index in [0_usize, 4, 1, 5, 2, 6, 3, 7] {
        frames.push(
            remaining
                .get_mut(index)
                .and_then(Option::take)
                .ok_or("interleaved PNG frame is missing")?,
        );
    }
    let source_frame = frames.first().ok_or("PNG fixture has no source frames")?;
    let late_payload = source_framed_record(8, &[])?;
    let late_frame = late_frame(source_frame, 100, 10, late_payload.as_slice())?;
    frames.push(late_frame);
    let evaluation =
        observe_with_one_omitted_frame(&frames, RecordSchemaProposalLimits::default())?;
    assert_eq!(evaluation.exact_artifact_matches, 1);
    assert!(!evaluation.pending);
    let accepted = evaluation
        .accepted_schema
        .as_ref()
        .ok_or("accepted record schema handoff is missing")?;
    assert_eq!(
        accepted.artifact_receipt.output_length,
        Some(fixture.plaintext.len())
    );
    assert!(accepted.artifact_receipt.output_sha256.is_some());
    assert_eq!(
        accepted.frame_indices,
        (0..frames.len()).collect::<Vec<_>>()
    );
    for (index, (identity, frame)) in accepted.frame_identities.iter().zip(&frames).enumerate() {
        assert_eq!(identity.frame_index, index);
        assert_eq!(identity.input_node_id, frame.input_node_id);
        assert_eq!(identity.context.session, frame.context.session);
        assert_eq!(identity.session_order, frame.session_order);
        assert_eq!(identity.stream_offset, frame.stream_offset);
        assert_eq!(identity.frame_byte_length, frame.bytes.len());
        assert_eq!(
            identity.frame_bytes_sha256,
            l2_workbench::sha256(&frame.bytes)
        );
    }
    Ok(())
}

#[test]
fn omitted_eligible_frame_conflict_prevents_sampled_artifact_validation() -> TestResult<()> {
    let fixture = crate::workbench::recovery_executor::record_discovery_tests::
        build_session_relative_fixture()?;
    let mut frames = source_framed_png_frames(&fixture.plaintext)?;
    let source_frame = frames.first().ok_or("PNG fixture has no source frames")?;
    let mut late_conflict = late_frame(source_frame, 100, 10, &source_frame.bytes)?;
    let declared_length = late_conflict
        .bytes
        .get_mut(7..9)
        .ok_or("source record has no declared-length field")?;
    declared_length.copy_from_slice(&u16::MAX.to_le_bytes());
    late_conflict.transformed_output_sha256 = l2_workbench::sha256(&late_conflict.bytes);
    frames.push(late_conflict);
    let evaluation =
        observe_with_one_omitted_frame(&frames, RecordSchemaProposalLimits::default())?;
    assert_eq!(evaluation.exact_artifact_matches, 0);
    assert!(evaluation.pending || !evaluation.survives);
    Ok(())
}

#[test]
fn full_application_respects_aggregate_record_and_metadata_budgets() -> TestResult<()> {
    let fixture = crate::workbench::recovery_executor::record_discovery_tests::
        build_session_relative_fixture()?;
    let mut frames = source_framed_png_frames(&fixture.plaintext)?;
    let source_frame = frames.first().ok_or("PNG fixture has no source frames")?;
    let late_payload = source_framed_record(8, &[])?;
    frames.push(late_frame(source_frame, 100, 10, &late_payload)?);

    let mut record_limited = RecordSchemaProposalLimits::default();
    record_limited.discovery.record_limits.max_records = 8;
    let record_evaluation = observe_with_one_omitted_frame(&frames, record_limited)?;
    assert_eq!(record_evaluation.exact_artifact_matches, 0);
    assert!(record_evaluation.pending);

    let schema = source_record_schema();
    let first_frame = frames.first().ok_or("PNG fixture has no source frames")?;
    let sample_report = l2_workbench::protocol::parse_records_with_limits(
        &first_frame.bytes,
        &schema,
        RecordSchemaProposalLimits::default()
            .discovery
            .record_limits,
    )?;
    let mut metadata_limited = RecordSchemaProposalLimits::default();
    metadata_limited.discovery.record_limits.max_report_bytes =
        sample_report.metadata_bytes().saturating_mul(8);
    let metadata_evaluation = observe_with_one_omitted_frame(&frames, metadata_limited)?;
    assert_eq!(metadata_evaluation.exact_artifact_matches, 0);
    assert!(metadata_evaluation.pending);

    let mut output_limited = RecordSchemaProposalLimits::default();
    output_limited.discovery.record_limits.max_output_bytes =
        fixture.plaintext.len().saturating_sub(1);
    let output_evaluation = observe_with_one_omitted_frame(&frames, output_limited)?;
    assert_eq!(output_evaluation.exact_artifact_matches, 0);
    assert!(output_evaluation.pending);
    Ok(())
}

fn observe_with_one_omitted_frame(
    frames: &[DecodedFrameOutput],
    limits: RecordSchemaProposalLimits,
) -> TestResult<SchemaAlternativeEvaluation> {
    let selected_count = frames.len().saturating_sub(1);
    let indices = selected_frame_indices(frames, selected_count);
    let hypothesis = l2_workbench::protocol::RecordSchemaHypothesis {
        schema: source_record_schema(),
        training_message_count: indices.selected_training.len(),
        held_out_message_count: indices.selected_heldout.len(),
        training_record_count: indices.selected_training.len(),
        held_out_record_count: indices.selected_heldout.len(),
    };
    let training_reports = parse_selected_frames(
        frames,
        &indices.selected_training,
        &hypothesis.schema,
        limits,
    )?;
    let heldout_reports = parse_selected_frames(
        frames,
        &indices.selected_heldout,
        &hypothesis.schema,
        limits,
    )?;
    let full_input_bytes = indices
        .all_frames
        .iter()
        .try_fold(0_usize, |total, index| {
            total.checked_add(frames.get(*index)?.bytes.len())
        })
        .ok_or("full input size overflowed or a frame is missing")?;
    let context = SchemaScreenContext {
        frames,
        frame_indices: &indices.all_frames,
        limits,
        parser_format: ArtifactValidationFormat::Png,
        artifact_policy: ArtifactValidationPolicy::default(),
        work_limit: 1024 * 1024,
        job: None,
        full_input_bytes,
    };
    let mut observer_work = 0;
    let mut evaluation = SchemaAlternativeEvaluation::default();
    let _control = observe_surviving_schema(
        &context,
        l2_workbench::protocol::RecordSchemaStrategy::FixedLayout,
        &hypothesis,
        &SurvivingSchemaInputs {
            selected_training_indices: &indices.selected_training,
            selected_heldout_indices: &indices.selected_heldout,
            all_training_indices: &indices.all_training,
            all_heldout_indices: &indices.all_heldout,
            training_reports: &training_reports,
            heldout_reports: &heldout_reports,
        },
        &mut observer_work,
        &mut evaluation,
    )?;
    assert!(observer_work <= context.work_limit);
    if evaluation.exact_artifact_matches > 0 {
        let accepted = evaluation
            .accepted_schema
            .as_ref()
            .ok_or("validated schema handoff is missing")?;
        assert_eq!(accepted.frame_indices, indices.all_frames);
        assert_eq!(accepted.frame_identities.len(), indices.all_frames.len());
        assert!(accepted.artifact_receipt.output_length.is_some());
        assert!(accepted.artifact_receipt.output_sha256.is_some());
    }
    evaluation.work_bytes = observer_work;
    Ok(evaluation)
}

struct FrameSelection {
    selected_training: Vec<usize>,
    selected_heldout: Vec<usize>,
    all_training: Vec<usize>,
    all_heldout: Vec<usize>,
    all_frames: Vec<usize>,
}

fn selected_frame_indices(frames: &[DecodedFrameOutput], selected_count: usize) -> FrameSelection {
    let mut indices = FrameSelection {
        selected_training: Vec::new(),
        selected_heldout: Vec::new(),
        all_training: Vec::new(),
        all_heldout: Vec::new(),
        all_frames: Vec::new(),
    };
    for (frame_index, frame) in frames.iter().enumerate() {
        indices.all_frames.push(frame_index);
        let training = frame.context.session <= 2;
        if training {
            indices.all_training.push(frame_index);
        } else if frame.context.session >= 3 {
            indices.all_heldout.push(frame_index);
        }
        if frame_index < selected_count {
            if training {
                indices.selected_training.push(frame_index);
            } else if frame.context.session >= 3 {
                indices.selected_heldout.push(frame_index);
            }
        }
    }
    indices
}

fn parse_selected_frames(
    frames: &[DecodedFrameOutput],
    indices: &[usize],
    schema: &l2_workbench::protocol::RecordSchema,
    limits: RecordSchemaProposalLimits,
) -> TestResult<Vec<RecordParseReport>> {
    indices
        .iter()
        .map(|index| {
            let frame = frames.get(*index).ok_or("selected frame is missing")?;
            Ok(l2_workbench::protocol::parse_records_with_limits(
                &frame.bytes,
                schema,
                limits.discovery.record_limits,
            )?)
        })
        .collect()
}

fn source_record_schema() -> l2_workbench::protocol::RecordSchema {
    l2_workbench::protocol::RecordSchema {
        records_offset: 0,
        count: l2_workbench::protocol::RecordCount::UntilEnd,
        identifier: l2_workbench::protocol::ByteField {
            offset: 3,
            width: 2,
        },
        sequence: l2_workbench::protocol::IntegerField {
            offset: 5,
            width: 2,
            byte_order: l2_workbench::protocol::ByteOrder::BigEndian,
        },
        length: l2_workbench::protocol::IntegerField {
            offset: 7,
            width: 2,
            byte_order: l2_workbench::protocol::ByteOrder::LittleEndian,
        },
        data_offset: 10,
        length_meaning: l2_workbench::protocol::RecordLengthMeaning::BytesAfterLengthField,
        sequence_base: 0,
        terminal_sequence: None,
    }
}

fn source_framed_png_frames(plaintext: &[u8]) -> TestResult<Vec<DecodedFrameOutput>> {
    let length = plaintext.len();
    let prefix_lengths = [6_usize, 5, 10, 6, 5, 6, 6];
    let mut boundaries = Vec::<usize>::with_capacity(9);
    boundaries.push(0);
    for fragment_length in prefix_lengths {
        let next = boundaries
            .last()
            .copied()
            .ok_or("PNG boundary list is empty")?
            .checked_add(fragment_length)
            .ok_or("PNG fragment boundary overflowed")?;
        boundaries.push(next);
    }
    boundaries.push(length);
    let sequence_sessions = [
        (4_u16, 1_u64),
        (7, 1),
        (5, 2),
        (6, 2),
        (0, 3),
        (3, 3),
        (1, 4),
        (2, 4),
    ];
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(sequence_sessions.len())
        .map_err(|source| format!("frame allocation failed: {source}"))?;
    for (sample_index, (sequence, session)) in sequence_sessions.into_iter().enumerate() {
        let start = *boundaries
            .get(usize::from(sequence))
            .ok_or("PNG fragment start is missing")?;
        let end = *boundaries
            .get(usize::from(sequence).saturating_add(1))
            .ok_or("PNG fragment end is missing")?;
        let fragment = plaintext
            .get(start..end)
            .ok_or("PNG fragment range is invalid")?;
        let bytes = source_framed_record(sequence, fragment)?;
        let mut frame = frame_with_identity(
            u64::try_from(sample_index)?
                .checked_add(1)
                .ok_or("sample identity overflowed")?,
            session,
            &bytes,
        );
        frame.session_order = session;
        frame.episode_node_id = session;
        frame.stream_offset = usize::from(sequence);
        frame.transformed_output_sha256 = l2_workbench::sha256(fragment);
        frame.preserved_header_end = Some(10);
        frame.payload_range = ByteRange {
            start: 10,
            end: bytes.len(),
        };
        frames.push(frame);
    }
    Ok(frames)
}

fn source_framed_record(sequence: u16, payload: &[u8]) -> TestResult<Vec<u8>> {
    let length = payload
        .len()
        .checked_add(1)
        .ok_or("record payload length overflowed")?;
    let encoded_length = u16::try_from(length)?;
    let mut body = Vec::new();
    body.push(0x2d);
    body.extend_from_slice(b"ID");
    body.extend_from_slice(&sequence.to_be_bytes());
    body.extend_from_slice(&encoded_length.to_le_bytes());
    body.push(0x6e);
    body.extend_from_slice(payload);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&u16::try_from(body.len())?.to_be_bytes());
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

fn length_prefixed_record(payload: &[u8]) -> TestResult<Vec<u8>> {
    let length = u8::try_from(payload.len())?;
    let mut record = vec![0, length];
    record.extend_from_slice(payload);
    Ok(record)
}

fn source_framed_frame(payload: &[u8]) -> DecodedFrameOutput {
    let mut frame = frame_with_identity(1, 1, payload);
    frame.preserved_header_end = Some(0);
    frame
}

fn clear_header_frame(payload: &[u8]) -> DecodedFrameOutput {
    let mut bytes = b"HEAD".to_vec();
    bytes.extend_from_slice(payload);
    let mut frame = frame_with_identity(1, 1, &bytes);
    frame.preserved_header_end = Some(4);
    frame.transformed_output_sha256 = l2_workbench::sha256(payload);
    frame.payload_range = ByteRange {
        start: 4,
        end: bytes.len(),
    };
    frame.bytes = bytes;
    frame
}

fn frame_with_identity(sample: u64, session: u64, payload: &[u8]) -> DecodedFrameOutput {
    DecodedFrameOutput {
        context: MessageContext {
            source: "source".to_owned(),
            scope: "scope".to_owned(),
            session,
            direction: Direction::FirstToSecond,
        },
        input_node_id: sample,
        seed_sample: sample.saturating_add(1),
        session_order: 0,
        transformed_output_sha256: l2_workbench::sha256(payload),
        direction_node_id: 3,
        episode_node_id: 4,
        stream_offset: 0,
        candidate_index: 0,
        parser_format: ArtifactValidationFormat::Png,
        expected_session_orders: vec![0],
        payload_range: ByteRange {
            start: 0,
            end: payload.len(),
        },
        preserved_header_end: None,
        bytes: payload.to_vec(),
    }
}

fn late_frame(
    source: &DecodedFrameOutput,
    sample: u64,
    order: u64,
    bytes: &[u8],
) -> TestResult<DecodedFrameOutput> {
    let mut frame = frame_with_identity(sample, source.context.session, bytes);
    frame.context = source.context.clone();
    frame.session_order = source.session_order;
    frame.episode_node_id = source.episode_node_id;
    frame.stream_offset = usize::try_from(order)?;
    frame.preserved_header_end = source.preserved_header_end;
    let payload_start = source.preserved_header_end.unwrap_or(0).min(bytes.len());
    frame.payload_range = ByteRange {
        start: payload_start,
        end: bytes.len(),
    };
    let transformed_payload = bytes
        .get(payload_start..)
        .ok_or("transformed payload start is outside the frame")?;
    frame.transformed_output_sha256 = l2_workbench::sha256(transformed_payload);
    Ok(frame)
}

fn report_with_sessions(discovery: &[u64], heldout: &[u64]) -> RelationalTransformReport {
    RelationalTransformReport {
        split_basis: HoldoutBasis::CompleteSessions,
        discovery_sessions: discovery.iter().copied().map(session).collect(),
        heldout_sessions: heldout.iter().copied().map(session).collect(),
        candidates: Vec::new(),
        equivalent_candidate_aliases: 0,
        candidates_examined: 0,
        omitted_candidates: 0,
        omitted_candidates_exact: true,
        candidate_limit_remaining: 0,
        locator_candidates_examined: 0,
        locator_candidate_limit_remaining: 0,
        work_bytes: 0,
        work_bytes_remaining: 0,
        search_exhaustive_within_plan: true,
        search_limits: Vec::new(),
        search_limit: None,
    }
}

fn candidate_options(
    parser_format: ArtifactValidationFormat,
    schema_limits: RecordSchemaProposalLimits,
    artifact_policy: ArtifactValidationPolicy,
    work_limit: usize,
) -> SchemaCandidateOptions<'static> {
    SchemaCandidateOptions {
        parser_format,
        schema_limits,
        artifact_policy,
        work_limit,
        job: None,
    }
}

fn session(session: u64) -> RelationalSessionId {
    RelationalSessionId {
        source: "source".to_owned(),
        scope: "scope".to_owned(),
        session,
    }
}
