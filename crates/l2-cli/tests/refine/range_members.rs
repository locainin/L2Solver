use l2_workbench::{
    artifact::{
        AnalysisOmission, ArtifactAnalysis, ArtifactAnalysisOptions, ArtifactOrigin,
        analyze_artifacts, zip::inspect_zip,
    },
    job::{MemoryBudget, MemoryClass, MemoryLease},
};
use std::error::Error;

fn merge_unanalyzed_member(work: usize) -> Result<(ArtifactAnalysis, MemoryLease), Box<dyn Error>> {
    let archive = inspect_zip(&super::structural_zip()?)?;
    assert_eq!(
        archive
            .entries
            .first()
            .and_then(|entry| entry.content.as_deref()),
        Some(b"member payload".as_slice())
    );
    let mut options = ArtifactAnalysisOptions::default();
    options.limits.max_depth = 0;
    options.limits.max_total_work_bytes = work;
    let mut report = analyze_artifacts(b"", ArtifactAnalysisOptions::default())?;
    report.artifacts.clear();
    report.omissions.clear();
    report.work_bytes = 0;
    let budget = MemoryBudget::new(1024 * 1024);
    let mut omissions = budget.try_reserve(MemoryClass::Executor, 0)?;
    crate::refine::range_members::append_members(&mut report, archive, 0, options, &mut omissions)?;
    Ok((report, omissions))
}

fn merge_source_member(
    work: usize,
    output: usize,
) -> Result<(ArtifactAnalysis, MemoryLease), Box<dyn Error>> {
    let archive = inspect_zip(&super::structural_zip()?)?;
    let mut options = ArtifactAnalysisOptions::default();
    options.limits.max_total_work_bytes = work;
    options.limits.max_total_output_bytes = output;
    let mut report = analyze_artifacts(b"", ArtifactAnalysisOptions::default())?;
    report.artifacts.clear();
    report.omissions.clear();
    report.work_bytes = 0;
    let budget = MemoryBudget::new(1024 * 1024);
    let mut omissions = budget.try_reserve(MemoryClass::Executor, 0)?;
    crate::refine::range_members::append_source_members(
        &mut report,
        archive,
        options,
        &mut omissions,
    )?;
    Ok((report, omissions))
}

#[test]
fn source_archive_member_output_limit_keeps_source_range_and_entry() -> Result<(), Box<dyn Error>> {
    let (report, _memory) = merge_source_member(1024, 1)?;
    assert_eq!(report.artifacts.len(), 0);
    let omission = report.omissions.first().ok_or("output omission missing")?;
    let omission = serde_json::to_value(omission)?;
    assert_eq!(
        omission.get("kind"),
        Some(&serde_json::json!("source_archive_member_output_limit"))
    );
    assert_eq!(omission.get("entry_index"), Some(&serde_json::json!(0)));
    assert_eq!(omission.get("length"), Some(&serde_json::json!(14)));
    assert_eq!(omission.get("remaining"), Some(&serde_json::json!(1)));
    assert_eq!(
        omission.pointer("/range/offset"),
        Some(&serde_json::json!(0))
    );
    Ok(())
}

#[test]
fn source_archive_member_work_limit_keeps_source_range_and_entry() -> Result<(), Box<dyn Error>> {
    let (report, _memory) = merge_source_member(0, 1024)?;
    assert_eq!(report.artifacts.len(), 0);
    let omission = report.omissions.first().ok_or("work omission missing")?;
    let omission = serde_json::to_value(omission)?;
    assert_eq!(
        omission.get("kind"),
        Some(&serde_json::json!("source_archive_member_work_limit"))
    );
    assert_eq!(omission.get("entry_index"), Some(&serde_json::json!(0)));
    assert_eq!(
        omission.get("stage"),
        Some(&serde_json::json!("artifact_identity"))
    );
    assert_eq!(omission.get("requested"), Some(&serde_json::json!(24)));
    assert_eq!(omission.get("remaining"), Some(&serde_json::json!(0)));
    assert_eq!(
        omission.pointer("/range/offset"),
        Some(&serde_json::json!(0))
    );
    Ok(())
}

#[test]
fn unanalysed_member_is_omitted_when_hash_work_cannot_be_admitted() -> Result<(), Box<dyn Error>> {
    let (report, omissions) = merge_unanalyzed_member(0)?;
    assert_eq!(report.artifacts.len(), 0);
    assert_eq!(report.work_bytes, 0);
    assert!(report.omissions.iter().any(|omission| matches!(
        omission,
        AnalysisOmission::WorkLimit {
            artifact_index: 0,
            requested: 24,
            remaining: 0,
            ..
        }
    )));
    drop(report);
    drop(omissions);
    Ok(())
}

#[test]
fn unanalysed_member_hash_is_debited_before_the_member_is_retained() -> Result<(), Box<dyn Error>> {
    let (report, omissions) = merge_unanalyzed_member(24)?;
    assert_eq!(report.work_bytes, 24);
    let artifact = report.artifacts.first().ok_or("member missing")?;
    assert_eq!(artifact.bytes, b"member payload");
    assert_eq!(artifact.sha256, l2_workbench::sha256(b"member payload"));
    assert!(artifact.origins.iter().any(|origin| matches!(
        origin,
        ArtifactOrigin::ArchiveMember {
            parent_index: 0,
            ..
        }
    )));
    drop(report);
    drop(omissions);
    Ok(())
}
