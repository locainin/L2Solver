use super::{AnalyzedSources, LoadedSource, SourceData, SourceReport};
use l2_workbench::{
    artifact::{ArtifactAnalysisOptions, analyze_artifacts_with_memory},
    job::{MemoryBudget, MemoryClass},
    sha256,
};
use std::error::Error;

#[test]
fn case_space_omission_admits_its_digest_and_report_before_allocation() -> Result<(), Box<dyn Error>>
{
    let bytes = b"source".to_vec();
    let source = LoadedSource {
        label: String::from("source"),
        data: SourceData::Memory {
            sha256: sha256(&bytes),
            bytes,
            _memory: None,
        },
    };
    let memory = MemoryBudget::new(1);
    let error = super::no_case_space(&source, 0, &memory)
        .err()
        .ok_or("omission report ignored shared memory")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(l2_workbench::job::MemoryError::Limit { .. })
    ));
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn failed_source_append_releases_report_memory_after_its_buffers() -> Result<(), Box<dyn Error>> {
    let memory = MemoryBudget::new(1024 * 1024);
    let mut sources = AnalyzedSources::new(1024 * 1024, 1, &memory)?;
    let baseline = memory.snapshot()?.used_bytes;
    let bytes = b"unchanged source bytes".to_vec();
    let source = LoadedSource {
        label: String::from("source"),
        data: SourceData::Memory {
            sha256: sha256(&bytes),
            bytes,
            _memory: None,
        },
    };
    let mut lease = memory.try_reserve(MemoryClass::Executor, 0)?;
    let report = analyze_artifacts_with_memory(
        source.bytes().ok_or("source bytes missing")?,
        source.digest(),
        ArtifactAnalysisOptions::default(),
        &mut lease,
    )?;
    let snapshot = memory.snapshot()?;
    let blocker = memory.try_reserve(
        MemoryClass::Cache,
        snapshot.limit_bytes - snapshot.used_bytes,
    )?;
    let reserved_bytes = blocker.bytes();
    let outcome = sources.append_source(
        0,
        &source,
        SourceReport {
            report,
            _source_digest_memory: None,
            report_memory: None,
            omission_memory: Some(lease),
        },
        &memory,
    );
    assert!(outcome.is_err());
    assert_eq!(memory.snapshot()?.used_bytes, baseline + reserved_bytes);
    drop(blocker);
    drop(sources);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn retained_omissions_keep_their_report_charge_until_the_source_record_drops()
-> Result<(), Box<dyn Error>> {
    let memory = MemoryBudget::new(1024 * 1024);
    let mut sources = AnalyzedSources::new(1024 * 1024, 1, &memory)?;
    let bytes = b"source with a skipped signature scan".to_vec();
    let source = LoadedSource {
        label: String::from("source"),
        data: SourceData::Memory {
            sha256: sha256(&bytes),
            bytes,
            _memory: None,
        },
    };
    let mut options = ArtifactAnalysisOptions::default();
    options.limits.max_signature_scan_bytes = 1;
    let mut lease = memory.try_reserve(MemoryClass::Executor, 0)?;
    let report = analyze_artifacts_with_memory(
        source.bytes().ok_or("source bytes missing")?,
        source.digest(),
        options,
        &mut lease,
    )?;
    assert_ne!(report.omissions.len(), 0);
    sources.append_source(
        0,
        &source,
        SourceReport {
            report,
            _source_digest_memory: None,
            report_memory: None,
            omission_memory: Some(lease),
        },
        &memory,
    )?;
    let record = sources
        .source_records
        .first()
        .ok_or("source record missing")?;
    assert_ne!(record.omissions.len(), 0);
    let retained = crate::refine::analysis_memory::omissions_owned_bytes(&record.omissions)?
        + record.label.capacity()
        + record.sha256.as_ref().map_or(0, String::capacity)
        + record.reason.as_ref().map_or(0, String::capacity);
    assert_eq!(record.omission_memory.bytes(), u64::try_from(retained)?);
    drop(sources);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}
