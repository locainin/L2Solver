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

#[test]
fn unanalysed_member_is_omitted_when_hash_work_cannot_be_admitted() -> Result<(), Box<dyn Error>> {
    let (report, omissions) = merge_unanalyzed_member(0)?;
    assert!(report.artifacts.is_empty());
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
