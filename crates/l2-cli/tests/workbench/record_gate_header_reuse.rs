use super::{
    GateStatus, SchemaPlanCache, assert_fresh_cached_artifact_validation, candidate_options,
    replace_transformed_payloads, report_with_sessions, source_framed_png_frames,
};
use crate::workbench::recovery_executor::relational::DecodedFrameOutput;
use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationPolicy},
    protocol::{ByteRange, RecordSchemaProposalLimits, RelationalTransformReport},
};
use serde_json::Value;
use std::error::Error;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const PROBE_WORK_LIMIT: usize = 16 * 1024;

#[path = "record_gate_checkpoint.rs"]
mod checkpoint;

struct LearnedHeader {
    cache: SchemaPlanCache,
    plaintext: Vec<u8>,
    frames: Vec<DecodedFrameOutput>,
    report: RelationalTransformReport,
}

impl LearnedHeader {
    fn new() -> TestResult<Self> {
        let fixture = crate::workbench::recovery_executor::record_discovery_tests::
            build_session_relative_fixture()?;
        let frames = source_framed_png_frames(&fixture.plaintext)?;
        let mut decoy_frames = source_framed_png_frames(&fixture.plaintext)?;
        replace_transformed_payloads(&mut decoy_frames, 0xa5)?;
        let report = report_with_sessions(&[1, 2], &[3, 4]);
        let mut cache = SchemaPlanCache::default();
        let learned = cache.screen_candidate(&decoy_frames, &report, options(64 * 1024 * 1024))?;
        assert_ne!(learned.status, GateStatus::ArtifactValidated);
        assert_eq!(cache.header_plans.len(), 1);
        Ok(Self {
            cache,
            plaintext: fixture.plaintext,
            frames,
            report,
        })
    }
}

fn options(work_limit: usize) -> super::SchemaCandidateOptions<'static> {
    candidate_options(
        ArtifactValidationFormat::Png,
        RecordSchemaProposalLimits::default(),
        ArtifactValidationPolicy::default(),
        work_limit,
    )
}

#[test]
fn whole_frame_transform_reuses_partial_models_without_promoting_changed_headers() -> TestResult {
    let mut fixture = LearnedHeader::new()?;
    let mut transformed = source_framed_png_frames(&fixture.plaintext)?;
    for frame in &mut transformed {
        frame.bytes.fill(0x5a);
        frame.preserved_header_end = None;
        frame.payload_range = ByteRange {
            start: 0,
            end: frame.bytes.len(),
        };
        frame.transformed_output_sha256 = l2_workbench::sha256(&frame.bytes);
    }
    let full_plans_before = fixture.cache.plans.len();

    let rejected_models =
        fixture
            .cache
            .screen_candidate(&transformed, &fixture.report, options(PROBE_WORK_LIMIT))?;

    assert_eq!(
        rejected_models.details.get("header_schema_plan_cache_hit"),
        Some(&Value::Bool(true)),
        "new decoded bytes should test the existing partial models before full inference"
    );
    assert_eq!(rejected_models.status, GateStatus::Pending);
    assert!(rejected_models.needs_full_inference());
    assert!(rejected_models.accepted_schema.is_none());
    assert!(rejected_models.work_bytes <= PROBE_WORK_LIMIT);
    assert!(
        rejected_models
            .details
            .get("header_schema_rebind_rejections")
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0)
    );
    assert_eq!(fixture.cache.plans.len(), full_plans_before);

    let recovered = fixture.cache.screen_candidate(
        &fixture.frames,
        &fixture.report,
        options(PROBE_WORK_LIMIT),
    )?;
    assert_fresh_cached_artifact_validation(&recovered, &fixture.plaintext, PROBE_WORK_LIMIT)?;
    Ok(())
}

#[test]
fn changed_payload_boundary_can_reuse_a_model_that_matches_actual_header_bytes() -> TestResult {
    let mut fixture = LearnedHeader::new()?;
    for frame in &mut fixture.frames {
        let payload = frame
            .bytes
            .get(11..)
            .ok_or("fixture prefix exceeds its frame")?;
        frame.transformed_output_sha256 = l2_workbench::sha256(payload);
        frame.preserved_header_end = Some(11);
        frame.payload_range.start = 11;
    }

    let recovered = fixture.cache.screen_candidate(
        &fixture.frames,
        &fixture.report,
        options(PROBE_WORK_LIMIT),
    )?;

    assert_fresh_cached_artifact_validation(&recovered, &fixture.plaintext, PROBE_WORK_LIMIT)?;
    Ok(())
}

#[test]
fn cached_header_match_without_receipt_work_remains_pending() -> TestResult {
    let mut fixture = LearnedHeader::new()?;
    let complete = fixture.cache.screen_candidate(
        &fixture.frames,
        &fixture.report,
        options(PROBE_WORK_LIMIT),
    )?;
    assert_eq!(complete.status, GateStatus::ArtifactValidated);
    assert!(complete.accepted_schema.is_some());
    let limit = complete
        .work_bytes
        .checked_sub(1)
        .ok_or("fixture did no work")?;

    let limited =
        fixture
            .cache
            .screen_candidate(&fixture.frames, &fixture.report, options(limit))?;
    assert_eq!(
        limited.details.get("header_schema_plan_cache_hit"),
        Some(&Value::Bool(true))
    );
    assert_eq!(limited.work_limited_at, Some(limit));
    assert_eq!(limited.status, GateStatus::Pending);
    assert!(limited.accepted_schema.is_none());
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum MembershipChange {
    Source,
    Scope,
    Session,
    InputNode,
}

#[test]
fn partial_model_cache_keeps_source_session_and_origin_membership_separate() -> TestResult {
    for change in [
        MembershipChange::Source,
        MembershipChange::Scope,
        MembershipChange::Session,
        MembershipChange::InputNode,
    ] {
        let mut fixture = LearnedHeader::new()?;
        change_membership(change, &mut fixture.frames, &mut fixture.report);

        let recovered = fixture.cache.screen_candidate(
            &fixture.frames,
            &fixture.report,
            options(64 * 1024 * 1024),
        )?;

        assert_eq!(
            recovered.details.get("header_schema_plan_cache_hit"),
            Some(&Value::Bool(false)),
            "changed {change:?} membership must not reuse another cohort's partial models"
        );
        assert_eq!(recovered.status, GateStatus::ArtifactValidated);
        let accepted = recovered
            .accepted_schema
            .ok_or("fresh schema identity is missing")?;
        assert_eq!(accepted.frame_identities.len(), fixture.frames.len());
        assert_eq!(
            accepted.artifact_receipt.output_sha256.as_deref(),
            Some(l2_workbench::sha256(&fixture.plaintext).as_str())
        );
        for (identity, frame) in accepted.frame_identities.iter().zip(&fixture.frames) {
            assert_eq!(identity.input_node_id, frame.input_node_id);
            assert_eq!(identity.context, frame.context);
        }
    }
    Ok(())
}

fn change_membership(
    change: MembershipChange,
    frames: &mut [DecodedFrameOutput],
    report: &mut RelationalTransformReport,
) {
    for frame in frames {
        match change {
            MembershipChange::Source => frame.context.source.push_str("-changed"),
            MembershipChange::Scope => frame.context.scope.push_str("-changed"),
            MembershipChange::Session => frame.context.session += 20,
            MembershipChange::InputNode => frame.input_node_id += 1000,
        }
    }
    for session in report
        .discovery_sessions
        .iter_mut()
        .chain(&mut report.heldout_sessions)
    {
        match change {
            MembershipChange::Source => session.source.push_str("-changed"),
            MembershipChange::Scope => session.scope.push_str("-changed"),
            MembershipChange::Session => session.session += 20,
            MembershipChange::InputNode => {}
        }
    }
}
