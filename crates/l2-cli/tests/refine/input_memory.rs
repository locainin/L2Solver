use std::{error::Error, io::Cursor};

use super::{
    AdmittedArchiveProbe, ObservedArchiveEnds, analyze_source_stream, source_zip_candidates,
};
use l2_workbench::{
    artifact::{AnalysisStatus, ArtifactAnalysis, ArtifactAnalysisOptions, StreamZipEnd},
    job::{MemoryBudget, MemoryClass, MemoryError},
};

#[test]
fn cache_snapshot_is_admitted_before_its_bytes_are_read() -> Result<(), Box<dyn Error>> {
    let path = tempfile::NamedTempFile::new()?;
    let original = b"source cache payload";
    std::fs::write(path.path(), original)?;
    let memory = MemoryBudget::new(u64::try_from(original.len() + 127)?);
    let mut lease = memory.try_reserve(MemoryClass::Executor, 0)?;
    let result = super::read_snapshot_with_memory(
        crate::input::regular_no_follow(path.path())?,
        original.len(),
        Some(original.len()),
        None,
        &mut lease,
    );
    assert!(matches!(
        result
            .as_ref()
            .err()
            .and_then(|error| crate::memory_error::find(error.as_ref())),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(lease.bytes(), 0);
    assert_eq!(std::fs::read(path.path())?, original);
    Ok(())
}

#[test]
fn cache_snapshot_keeps_bytes_and_digest_charged_until_the_owner_drops()
-> Result<(), Box<dyn Error>> {
    let path = tempfile::NamedTempFile::new()?;
    let original = b"source cache payload";
    std::fs::write(path.path(), original)?;
    let memory = MemoryBudget::new(4096);
    let mut lease = memory.try_reserve(MemoryClass::Executor, 0)?;
    let (bytes, digest) = super::read_snapshot_with_memory(
        crate::input::regular_no_follow(path.path())?,
        original.len(),
        Some(original.len()),
        Some(&l2_workbench::sha256(original)),
        &mut lease,
    )?;
    assert_eq!(bytes, original);
    assert_eq!(digest, l2_workbench::sha256(original));
    assert!(lease.bytes() >= u64::try_from(bytes.capacity() + digest.capacity())?);
    drop(bytes);
    drop(digest);
    drop(lease);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn png_boundary_digest_keeps_its_scratch_charge_after_the_scanner_drops()
-> Result<(), Box<dyn Error>> {
    let bytes = crate::refine::tests::structural_png()?;
    let budget = MemoryBudget::new(2 * 1024 * 1024);
    let mut scanned = analyze_source_stream(
        &mut Cursor::new(&bytes),
        bytes.len(),
        ArtifactAnalysisOptions::default(),
        None,
        &budget,
        false,
    )?;
    let boundary = scanned.png.take().ok_or("PNG boundary is missing")?;
    let digest_bytes = u64::try_from(boundary.boundary.sha256.capacity())?;
    assert_eq!(boundary.memory.bytes(), digest_bytes);
    assert_eq!(boundary.boundary.sha256, l2_workbench::sha256(&bytes));
    drop(scanned);
    assert_eq!(budget.snapshot()?.used(MemoryClass::Executor), digest_bytes);
    drop(boundary);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn zip_candidate_growth_returns_typed_pressure_and_releases_its_probe() -> Result<(), Box<dyn Error>>
{
    let limit = 64 + std::mem::size_of::<StreamZipEnd>() - 1;
    let budget = MemoryBudget::new(u64::try_from(limit)?);
    let mut ends = ObservedArchiveEnds {
        tail: Some(crate::refine::range_zip::ZipCandidate {
            length: 1,
            multiple_boundaries: false,
        }),
        probe: AdmittedArchiveProbe {
            prefix_sha256: None,
            stream: None,
            memory: budget.try_reserve(MemoryClass::Executor, 0)?,
        },
    };
    let mut report = ArtifactAnalysis {
        source_sha256: "a".repeat(64),
        source_length: 1,
        artifacts: Vec::new(),
        status: AnalysisStatus::Partial,
        omissions: Vec::new(),
        region_transform_reports: Vec::new(),
        work_bytes: 0,
        zip_expanded_work_bytes: 0,
    };
    let mut omission_memory = budget.try_reserve(MemoryClass::Executor, 0)?;
    let result = source_zip_candidates(&mut ends, &mut report, &mut omission_memory);
    assert!(matches!(
        result
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<MemoryError>()),
        Some(MemoryError::Limit { .. })
    ));
    assert!(report.omissions.is_empty());
    drop(ends);
    drop(omission_memory);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn non_png_stream_does_not_retain_a_digest_boundary_charge() -> Result<(), Box<dyn Error>> {
    let bytes = b"plain input";
    let budget = MemoryBudget::new(2 * 1024 * 1024);
    let scanned = analyze_source_stream(
        &mut Cursor::new(bytes),
        bytes.len(),
        ArtifactAnalysisOptions::default(),
        None,
        &budget,
        false,
    )?;
    assert!(scanned.png.is_none());
    assert_eq!(
        scanned.source_digest_memory.bytes(),
        u64::try_from(scanned.scanned.analysis.source_sha256.capacity())?
    );
    drop(scanned);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn source_prefix_and_zip_observation_keep_their_live_charges() -> Result<(), Box<dyn Error>> {
    let bytes = crate::refine::tests::structural_zip()?;
    let checkpoint = bytes.len() / 2;
    let budget = MemoryBudget::new(2 * 1024 * 1024);
    let scanned = analyze_source_stream(
        &mut Cursor::new(&bytes),
        bytes.len(),
        ArtifactAnalysisOptions::default(),
        Some(checkpoint),
        &budget,
        false,
    )?;
    let expected_source = u64::try_from(scanned.scanned.analysis.source_sha256.capacity())?;
    let prefix = scanned
        .probe
        .prefix_sha256
        .as_ref()
        .ok_or("prefix digest missing")?;
    let observation = scanned
        .probe
        .stream
        .as_ref()
        .ok_or("ZIP observation missing")?;
    let expected_probe = prefix.capacity()
        + observation.candidates.capacity()
            * std::mem::size_of::<l2_workbench::artifact::StreamZipEnd>()
        + observation
            .candidates
            .iter()
            .map(|candidate| candidate.sha256.capacity())
            .sum::<usize>();
    assert!(!observation.candidates.is_empty());
    assert_eq!(scanned.source_digest_memory.bytes(), expected_source);
    assert_eq!(scanned.probe.memory.bytes(), u64::try_from(expected_probe)?);
    assert!(budget.snapshot()?.used_bytes >= expected_source + u64::try_from(expected_probe)?);
    drop(scanned);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
