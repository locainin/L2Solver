use std::{error::Error, mem::size_of};

use super::{AnalyzedSources, SourceReport};
use crate::refine::analysis_memory as retained;
use crate::refine::{
    file_artifact::{DerivedArtifact, DerivedFile, FileArtifact},
    input::{AdmittedPngBoundary, LoadedSource, SourceData},
    output::ArtifactRecord,
};
use l2_workbench::{
    artifact::{
        AnalysisBoundary, AnalysisFormat, AnalyzedArtifact, ArtifactOrigin,
        ArtifactValidationState, FileRange, StreamPngBoundary, ValidationSummary,
    },
    job::{MemoryBudget, MemoryClass, MemoryError},
};

type TestResult = Result<(), Box<dyn Error>>;

fn png_boundary() -> StreamPngBoundary {
    StreamPngBoundary {
        range: FileRange {
            offset: 0,
            length: 9,
        },
        sha256: "a".repeat(64),
        chunk_count: 1,
    }
}

fn admitted_png_boundary(
    budget: &MemoryBudget,
    boundary: StreamPngBoundary,
) -> Result<AdmittedPngBoundary, Box<dyn Error>> {
    let memory = budget.try_reserve(
        MemoryClass::Executor,
        u64::try_from(boundary.sha256.capacity())?,
    )?;
    Ok(AdmittedPngBoundary { boundary, memory })
}

fn member_origin(preview_length: usize) -> ArtifactOrigin {
    ArtifactOrigin::ArchiveMember {
        parent_index: 0,
        archive_range: FileRange {
            offset: 0,
            length: 1,
        },
        entry_index: 0,
        raw_name_sha256: "a".repeat(64),
        raw_name_hex_preview: "b".repeat(preview_length),
        compressed_size: 1,
        expanded_size: 1,
    }
}

fn artifact(origin: ArtifactOrigin) -> AnalyzedArtifact {
    AnalyzedArtifact {
        index: 0,
        origins: vec![origin],
        sha256: "c".repeat(64),
        signature_match_count: 0,
        signatures_scanned: false,
        validation: ValidationSummary {
            state: ArtifactValidationState::Validated,
            format: Some(AnalysisFormat::Png),
            boundary: Some(AnalysisBoundary::PngIend),
            range: Some(FileRange {
                offset: 0,
                length: 1,
            }),
            structure_count: 1,
        },
        bytes: vec![1],
    }
}

#[test]
fn retained_vector_growth_rejects_when_old_and_new_buffers_cannot_overlap() -> TestResult {
    let element_bytes = size_of::<u64>();
    let budget = MemoryBudget::new(u64::try_from(12 * element_bytes - 1)?);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let mut values = Vec::<u64>::new();
    for value in 0..4 {
        retained::grow_vec(&mut values, &mut lease, 1)?;
        values.push(value);
    }
    let before = lease.bytes();
    let result = retained::grow_vec(&mut values, &mut lease, 1);
    assert!(matches!(
        result
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<MemoryError>()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(values, [0, 1, 2, 3]);
    assert_eq!(lease.bytes(), before);
    assert_eq!(budget.snapshot()?.used_bytes, before);
    drop(values);
    drop(lease);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn exact_origin_growth_requires_old_and_new_buffers_to_overlap() -> TestResult {
    let element_bytes = size_of::<u64>();
    let budget = MemoryBudget::new(u64::try_from(9 * element_bytes - 1)?);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let mut values = Vec::<u64>::new();
    retained::grow_vec_exact(&mut values, &mut lease, 4)?;
    values.extend([0, 1, 2, 3]);
    let before = lease.bytes();
    let result = retained::grow_vec_exact(&mut values, &mut lease, 1);
    assert!(matches!(
        result
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<MemoryError>()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(values, [0, 1, 2, 3]);
    assert_eq!(lease.bytes(), before);
    assert_eq!(budget.snapshot()?.used_bytes, before);
    Ok(())
}

#[test]
fn moved_origin_and_digest_stay_charged_until_analysis_drops() -> TestResult {
    let input = artifact(member_origin(40));
    let budget = MemoryBudget::new(64 * 1024);
    let mut analysis = AnalyzedSources::new(4_096, 0, &budget)?;
    let owned = input.bytes.capacity()
        + input.sha256.capacity()
        + input.origins.capacity() * size_of::<ArtifactOrigin>()
        + input
            .origins
            .first()
            .ok_or("origin missing")?
            .owned_heap_bytes()
            .ok_or("origin size overflow")?;
    let artifacts = vec![input];
    let owned = owned + artifacts.capacity() * size_of::<AnalyzedArtifact>();
    let lease = budget.try_reserve(MemoryClass::Executor, u64::try_from(owned)?)?;
    let mut report = SourceReport {
        report: l2_workbench::artifact::ArtifactAnalysis {
            source_sha256: String::new(),
            source_length: 1,
            artifacts,
            status: l2_workbench::artifact::AnalysisStatus::Complete,
            omissions: Vec::new(),
            region_transform_reports: Vec::new(),
            work_bytes: 0,
            zip_expanded_work_bytes: 0,
        },
        _source_digest_memory: None,
        _report_memory: Some(lease),
        omission_memory: None,
    };
    analysis.append_artifacts(0, &mut report)?;
    drop(report);
    let record = analysis
        .artifact_records
        .first()
        .ok_or("artifact record missing")?;
    let record_bytes = analysis.artifact_records.capacity() * size_of::<ArtifactRecord>()
        + record
            .origin
            .owned_heap_bytes()
            .ok_or("origin size overflow")?
        + record.sha256.capacity();
    assert_eq!(
        budget.snapshot()?.used(MemoryClass::Executor),
        u64::try_from(record_bytes)?
    );
    drop(analysis);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn source_png_metadata_stays_charged_until_the_file_artifact_drops() -> TestResult {
    let budget = MemoryBudget::new(16 * 1024);
    let boundary = admitted_png_boundary(&budget, png_boundary())?;
    let file = FileArtifact::png(7, 0, 0, boundary)?;
    let owned = file.sha256.capacity()
        + file.file_name.capacity()
        + file.origins.capacity() * size_of::<crate::refine::file_artifact::FileOrigin>()
        + file.provenance.capacity()
            * size_of::<crate::workbench::artifact_export::ArtifactProvenance>()
        + file
            .provenance
            .first()
            .map_or(0, |origin| origin.kind.capacity());
    assert_eq!(budget.snapshot()?.used_bytes, u64::try_from(owned)?);
    drop(file);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn source_png_metadata_returns_typed_pressure_without_a_retained_charge() -> TestResult {
    let budget = MemoryBudget::new(64);
    let boundary = admitted_png_boundary(&budget, png_boundary())?;
    let result = FileArtifact::png(7, 0, 0, boundary);
    assert!(matches!(
        result
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<MemoryError>()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn source_zip_metadata_admits_the_archive_digest_copy() -> TestResult {
    let budget = MemoryBudget::new(16 * 1024);
    let digest = "d".repeat(64);
    let file = FileArtifact::zip(7, 0, 0, 12, &digest, 1, &budget)?;
    assert_eq!(file.sha256, digest);
    assert!(budget.snapshot()?.used_bytes >= u64::try_from(file.sha256.capacity())?);
    drop(file);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn source_file_vector_and_artifact_metadata_share_the_job_budget() -> TestResult {
    let budget = MemoryBudget::new(64 * 1024);
    let bytes = vec![1];
    let digest = l2_workbench::sha256(&bytes);
    let source = LoadedSource {
        label: "source".to_owned(),
        data: SourceData::Memory {
            bytes,
            sha256: digest.clone(),
            _memory: None,
        },
    };
    let mut analysis = AnalyzedSources::new(4_096, 0, &budget)?;
    let mut boundary = png_boundary();
    boundary.range.length = 1;
    let boundary = admitted_png_boundary(&budget, boundary)?;
    analysis.append_file_png(0, 0, &source, &digest, boundary)?;
    let file = analysis
        .file_artifacts
        .first()
        .ok_or("file artifact missing")?;
    let minimum = analysis.file_artifacts.capacity() * size_of::<FileArtifact>()
        + file.sha256.capacity()
        + file.file_name.capacity()
        + file.origins.capacity() * size_of::<crate::refine::file_artifact::FileOrigin>()
        + file.provenance.capacity()
            * size_of::<crate::workbench::artifact_export::ArtifactProvenance>()
        + file
            .provenance
            .first()
            .map_or(0, |origin| origin.kind.capacity());
    assert_eq!(
        budget.snapshot()?.used(MemoryClass::Executor),
        u64::try_from(minimum)?
    );
    drop(analysis);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn source_digest_charge_survives_until_a_failed_report_handoff_drops_the_report() -> TestResult {
    let budget = MemoryBudget::new(64 * 1024);
    let mut analysis = AnalyzedSources::new(4_096, 1, &budget)?;
    let baseline = budget.snapshot()?.used_bytes;
    let bytes = vec![1];
    let digest = l2_workbench::sha256(&bytes);
    let source = LoadedSource {
        label: "source".to_owned(),
        data: SourceData::Memory {
            bytes,
            sha256: digest.clone(),
            _memory: None,
        },
    };
    let digest_memory =
        budget.try_reserve(MemoryClass::Executor, u64::try_from(digest.capacity())?)?;
    let report = SourceReport {
        report: l2_workbench::artifact::ArtifactAnalysis {
            source_sha256: digest,
            source_length: 1,
            artifacts: Vec::new(),
            status: l2_workbench::artifact::AnalysisStatus::Complete,
            omissions: Vec::new(),
            region_transform_reports: Vec::new(),
            work_bytes: 0,
            zip_expanded_work_bytes: 0,
        },
        _source_digest_memory: Some(digest_memory),
        _report_memory: None,
        omission_memory: None,
    };
    let used = budget.snapshot()?.used_bytes;
    let blocker = budget.try_reserve(MemoryClass::Cache, 64 * 1024 - used)?;
    let result = analysis.append_source(0, &source, report, &budget);
    assert!(matches!(
        result
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<MemoryError>()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(budget.snapshot()?.used_bytes, baseline + blocker.bytes());
    assert!(analysis.source_records.is_empty());
    drop(blocker);
    drop(analysis);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn derived_file_metadata_reuses_its_existing_lease() -> TestResult {
    let budget = MemoryBudget::new(64 * 1024);
    let spool_memory = budget.try_reserve(MemoryClass::Executor, 0)?;
    let spool = DerivedFile::new(tempfile::tempfile()?, spool_memory, Vec::new());
    let derived = DerivedArtifact::new(spool, &budget, 1)?;
    let before = budget.snapshot()?.used_bytes;
    let file = FileArtifact::derived_png(7, 0, 0, png_boundary(), 9, derived)?;
    assert_eq!(budget.snapshot()?.used_bytes, before);
    drop(file);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
