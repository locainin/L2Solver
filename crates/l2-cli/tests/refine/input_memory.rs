use std::{error::Error, io::Cursor};

use super::{
    AdmittedArchiveProbe, ObservedArchiveEnds, analyze_source_stream, source_zip_candidates,
};
use l2_workbench::{
    artifact::{AnalysisStatus, ArtifactAnalysis, ArtifactAnalysisOptions, StreamZipEnd},
    job::{MemoryBudget, MemoryClass, MemoryError},
};

#[test]
fn loaded_source_records_and_digests_remain_admitted_until_dropped() -> Result<(), Box<dyn Error>> {
    let file = tempfile::NamedTempFile::new()?;
    let original = b"source identity";
    std::fs::write(file.path(), original)?;
    let input = crate::refine::prepare_input_set(file.path())?;
    let memory = MemoryBudget::new(1024 * 1024);
    let sources = super::read_sources(
        &input,
        1024,
        1024,
        &l2_workbench::job::Job::new("source"),
        &memory,
    )?;
    let source = sources.first().ok_or("source missing")?;
    assert_eq!(source.bytes(), Some(original.as_slice()));
    assert_eq!(
        source.digest(),
        Some(l2_workbench::sha256(original).as_str())
    );
    assert!(
        memory.snapshot()?.used(MemoryClass::Base)
            >= u64::try_from(
                original.len()
                    + 64
                    + source.label.capacity()
                    + std::mem::size_of::<super::LoadedSource>(),
            )?
    );
    drop(sources);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn loaded_source_metadata_is_admitted_before_creating_records() -> Result<(), Box<dyn Error>> {
    let file = tempfile::NamedTempFile::new()?;
    std::fs::write(file.path(), b"source")?;
    let input = crate::refine::prepare_input_set(file.path())?;
    let memory = MemoryBudget::new(1);
    let error = super::read_sources(
        &input,
        1024,
        1024,
        &l2_workbench::job::Job::new("source"),
        &memory,
    )
    .err()
    .ok_or("source metadata bypassed admission")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    assert_eq!(std::fs::read(file.path())?, b"source");
    Ok(())
}

#[test]
fn memory_source_refusal_precedes_its_read_budget_and_file_reads() -> Result<(), Box<dyn Error>> {
    let file = tempfile::NamedTempFile::new()?;
    let original = b"source memory admission";
    std::fs::write(file.path(), original)?;
    let job = l2_workbench::job::Job::new("source admission");
    let input_memory = MemoryBudget::new(4096);
    let input = super::prepare_input_set_with_limit(file.path(), u64::MAX, &job, &input_memory)?;
    let before = input.budget.remaining();
    let memory = MemoryBudget::new(u64::try_from(original.len() + 127)?);
    let error = super::read_memory_source(
        &input,
        input.sources.first().ok_or("source missing")?,
        std::fs::File::open(file.path())?,
        original.len(),
        original.len(),
        &job,
        &memory,
    )
    .err()
    .ok_or("source bytes bypassed memory admission")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(input.budget.remaining(), before);
    assert_eq!(
        job.snapshot()?
            .counters
            .get(&l2_workbench::job::Counter::SourceReadBytes),
        Some(&0)
    );
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    assert_eq!(std::fs::read(file.path())?, original);
    Ok(())
}

#[test]
fn source_fingerprint_metadata_is_admitted_and_released_with_its_owner()
-> Result<(), Box<dyn Error>> {
    let file = tempfile::NamedTempFile::new()?;
    std::fs::write(file.path(), b"fingerprint source")?;
    let memory = MemoryBudget::new(1024 * 1024);
    let job = l2_workbench::job::Job::new("fingerprint");
    let input = super::prepare_input_set_with_limit(file.path(), u64::MAX, &job, &memory)?;
    let baseline = memory.snapshot()?.used_bytes;
    let blocker = memory.try_reserve(
        MemoryClass::Cache,
        memory.snapshot()?.limit_bytes - baseline,
    )?;
    let error = super::fingerprint_sources(&input, 1024, 1024, &job)
        .err()
        .ok_or("fingerprint bypassed shared admission")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(memory.snapshot()?.used_bytes, baseline + blocker.bytes());
    drop(blocker);
    let sampled = super::fingerprint_sources(&input, 1024, 1024, &job)?;
    assert!(memory.snapshot()?.used_bytes > baseline);
    drop(sampled);
    assert_eq!(memory.snapshot()?.used_bytes, baseline);
    drop(input);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn enlarged_manifest_is_rejected_before_a_recheck_reads_it() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let manifest = directory.path().join("manifest.json");
    std::fs::write(directory.path().join("one.bin"), b"a")?;
    std::fs::write(
        &manifest,
        br#"{"schema_version":1,"artifacts":[{"file":"one.bin","byte_length":1}]}"#,
    )?;
    let memory = MemoryBudget::new(1024 * 1024);
    let job = l2_workbench::job::Job::new("manifest recheck");
    let input = super::prepare_input_set_with_limit(directory.path(), u64::MAX, &job, &memory)?;
    let remaining = memory.snapshot()?.limit_bytes - memory.snapshot()?.used_bytes;
    let blocker = memory.try_reserve(MemoryClass::Cache, remaining)?;
    super::ensure_manifest_unchanged(&input, &job)?;

    let replacement = vec![b' '; 128 * 1024];
    std::fs::write(&manifest, &replacement)?;
    let before = job.snapshot()?.counters;
    let error = super::ensure_manifest_unchanged(&input, &job)
        .expect_err("a differently sized manifest must be rejected");
    assert!(error.to_string().contains("manifest changed"));
    let after = job.snapshot()?.counters;
    assert_eq!(
        before.get(&l2_workbench::job::Counter::SourceReadBytes),
        after.get(&l2_workbench::job::Counter::SourceReadBytes)
    );
    assert_eq!(std::fs::read(&manifest)?, replacement);
    drop(blocker);
    drop(input);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

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
