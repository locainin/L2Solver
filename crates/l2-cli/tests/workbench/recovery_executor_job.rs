use super::tests::{stored_zip_entries, tiny_png};
use super::*;
use crate::arguments::RecoveryProfile;
use l2_workbench::{
    derivation::Operation,
    evidence::Case,
    job::{Counter, Job, Phase, PhaseState},
    recovery::RecoveryTask,
};
use std::error::Error;

#[test]
fn cancelled_job_stops_recovery_before_policy_scans_or_case_mutation() -> Result<(), Box<dyn Error>>
{
    let mut case = Case::new();
    let job = Job::new("cancelled recovery");
    job.request_cancel();

    let error = recover_case_with_job(&mut case, RecoveryProfile::Fast, 1024 * 1024, Some(&job))
        .err()
        .ok_or("cancelled recovery unexpectedly completed")?;

    assert!(error.to_string().contains("cancellation was requested"));
    assert!(case.nodes().is_empty());
    assert_eq!(
        job.snapshot()?
            .phase(Phase::FramingRecordDiscovery)
            .map(|phase| phase.state),
        Some(PhaseState::Pending),
    );
    Ok(())
}

#[test]
fn job_aware_recovery_accepts_profile_and_memory_limits() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let job = Job::new("empty capture");
    let summary = recover_case_with_job(
        &mut case,
        RecoveryProfile::Fast,
        8 * 1024 * 1024,
        Some(&job),
    )?;

    assert!(summary.case_evidence_collection_complete);
    assert!(case.nodes().is_empty());
    Ok(())
}

#[test]
fn recovery_job_counts_committed_validated_artifacts_and_archive_members()
-> Result<(), Box<dyn Error>> {
    let (png, archive) = archive_with_duplicate_png_members()?;
    let mut case = Case::new();
    case.add_bytes_node(
        "archive_member",
        &png,
        Vec::new(),
        serde_json::json!({"fixture":"already retained before this run"}),
    )?;
    let archive_node =
        case.add_bytes_node("http_body", &archive, Vec::new(), serde_json::json!({}))?;
    let job = Job::new("archive recovery progress");

    let summary = recover_case_with_job(
        &mut case,
        RecoveryProfile::Fast,
        8 * 1024 * 1024,
        Some(&job),
    )?;
    let snapshot = job.snapshot()?;
    let validated_artifacts = snapshot
        .counters
        .get(&Counter::ValidatedArtifacts)
        .copied()
        .unwrap_or_default();
    let expanded_members = snapshot
        .counters
        .get(&Counter::ExpandedMembers)
        .copied()
        .unwrap_or_default();
    let retained_members = u64::try_from(
        case.nodes()
            .iter()
            .filter(|node| node.kind == "archive_member")
            .count(),
    )?;
    let committed_members = u64::try_from(
        case.nodes()
            .iter()
            .filter(|node| {
                node.kind == "archive_member"
                    && node
                        .details
                        .get("archive_node")
                        .and_then(serde_json::Value::as_u64)
                        == Some(archive_node)
            })
            .count(),
    )?;

    assert_eq!(summary.validated_artifact_count, 2);
    assert_eq!(retained_members, 3);
    assert_eq!(committed_members, 2);
    assert_eq!(
        validated_artifacts,
        u64::try_from(summary.validated_artifact_count)?
    );
    assert_eq!(expanded_members, committed_members);
    Ok(())
}

fn archive_with_duplicate_png_members() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let png = tiny_png()?;
    let archive = stored_zip_entries(&[
        (b"first.png", png.as_slice()),
        (b"second.png", png.as_slice()),
    ])?;
    Ok((png, archive))
}

#[test]
fn transform_progress_never_displays_literal_operation_parameters() -> Result<(), Box<dyn Error>> {
    let job = Job::new("redacted transform progress");
    job.start(Phase::AssemblyValidation, None)?;
    let task = RecoveryTask::transform(Operation::XorRepeat {
        key: vec![0xca, 0xfe, 0xba, 0xbe],
        offset: 0,
    });

    JobProgress::new(job.clone()).begin_candidate(&task)?;

    let snapshot = job.snapshot()?;
    assert_eq!(
        snapshot
            .phase(Phase::AssemblyValidation)
            .and_then(|phase| phase.message.as_deref()),
        Some("running transform")
    );
    assert!(!serde_json::to_string(&snapshot)?.contains("202,254,186,190"));
    Ok(())
}
