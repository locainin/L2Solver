use super::{
    image_support::structural_png,
    zip_support::{FixtureEntry, build_zip},
};
use l2_workbench::{
    artifact::{
        AnalyzerError, ArtifactAnalysisOptions, ArtifactOrigin, analyze_artifacts,
        analyze_artifacts_with_memory,
    },
    job::{MemoryBudget, MemoryClass, MemoryError},
    sha256,
};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

fn nested_archive() -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let png = structural_png(&[])?;
    let inner = build_zip(&[FixtureEntry::stored(b"image.png", &png)])?;
    let outer = build_zip(&[FixtureEntry::stored(b"inner.zip", &inner)])?;
    Ok((outer, inner, png))
}

#[test]
fn analyzer_admits_source_copy_before_allocation_and_preserves_existing_charge() -> TestResult {
    let memory = MemoryBudget::new(1024);
    let mut retained = memory.try_reserve(MemoryClass::Executor, 100)?;
    let blocker = memory.try_reserve(MemoryClass::Cache, 924)?;
    let source = b"source whose retained copy must be admitted";
    let result = analyze_artifacts_with_memory(
        source,
        Some(&sha256(source)),
        ArtifactAnalysisOptions::default(),
        &mut retained,
    );
    assert!(matches!(
        result,
        Err(AnalyzerError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(retained.bytes(), 100);
    assert_eq!(memory.snapshot()?.used_bytes, 1024);
    drop(blocker);
    drop(retained);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn nested_zip_members_keep_capacity_charged_in_one_near_full_working_set() -> TestResult {
    let (outer, inner, png) = nested_archive()?;
    let root = MemoryBudget::new(16 * 1024 * 1024);
    let work = root.try_working_set(8 * 1024 * 1024)?;
    let before = root.snapshot()?;
    let outside = root.try_reserve(
        MemoryClass::Cache,
        before.limit_bytes - before.used_bytes - before.working_sets.reserved_bytes,
    )?;
    let mut retained = work.budget().try_reserve(MemoryClass::Executor, 0)?;
    let options = ArtifactAnalysisOptions::default();
    let report =
        analyze_artifacts_with_memory(&outer, Some(&sha256(&outer)), options, &mut retained)?;
    assert!(
        report
            .artifacts
            .iter()
            .any(|artifact| artifact.bytes == outer)
    );
    assert!(
        report
            .artifacts
            .iter()
            .any(|artifact| artifact.bytes == inner)
    );
    assert!(report.artifacts.iter().any(|artifact| {
        artifact.bytes == png
            && artifact
                .origins
                .iter()
                .any(|origin| matches!(origin, ArtifactOrigin::ArchiveMember { .. }))
    }));
    let live_payload = report
        .artifacts
        .iter()
        .map(|artifact| artifact.bytes.capacity())
        .sum::<usize>();
    assert!(retained.bytes() >= u64::try_from(live_payload)?);
    let legacy = analyze_artifacts(&outer, options)?;
    assert_eq!(report, legacy);
    drop(legacy);
    drop(report);
    drop(retained);
    drop(outside);
    drop(work);
    assert_eq!(root.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn analyzer_pressure_rolls_back_pending_and_nested_output_charges() -> TestResult {
    let (outer, _, _) = nested_archive()?;
    let options = ArtifactAnalysisOptions::default();
    let ample = MemoryBudget::new(16 * 1024 * 1024);
    let mut lease = ample.try_reserve(MemoryClass::Executor, 0)?;
    let report = analyze_artifacts_with_memory(&outer, Some(&sha256(&outer)), options, &mut lease)?;
    let peak = ample.snapshot()?.peak_bytes;
    assert!(peak > 0);
    drop(report);
    drop(lease);
    assert_eq!(ample.snapshot()?.used_bytes, 0);

    let constrained = MemoryBudget::new(peak - 1);
    let mut lease = constrained.try_reserve(MemoryClass::Executor, 0)?;
    let result = analyze_artifacts_with_memory(&outer, Some(&sha256(&outer)), options, &mut lease);
    assert!(matches!(
        result,
        Err(AnalyzerError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(lease.bytes(), 0);
    assert_eq!(constrained.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn gzip_transform_admits_small_actual_output_without_reserving_its_policy_ceiling() -> TestResult {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    let content = vec![0x91; 32 * 1024];
    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    gzip.write_all(&content)?;
    let compressed = gzip.finish()?;
    let memory_limit = 1536 * 1024;
    let memory = MemoryBudget::new(memory_limit);
    let mut lease = memory.try_reserve(MemoryClass::Executor, 0)?;
    let options = ArtifactAnalysisOptions::default();
    assert!(
        u64::try_from(options.limits.max_transform_output_bytes)?
            + l2_workbench::derivation::STREAM_WORKSPACE_BYTES
            > memory_limit
    );
    let report = analyze_artifacts_with_memory(
        &compressed,
        Some(&sha256(&compressed)),
        options,
        &mut lease,
    )?;
    assert!(
        report
            .artifacts
            .iter()
            .any(|artifact| artifact.bytes == content)
    );
    let capacity = report
        .artifacts
        .iter()
        .map(|artifact| artifact.bytes.capacity())
        .sum::<usize>();
    assert!(lease.bytes() >= u64::try_from(capacity)?);
    drop(report);
    drop(lease);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn analyzer_computes_an_admitted_digest_and_keeps_source_bytes_unchanged() -> TestResult {
    let source = b"source with no supplied identity".to_vec();
    let original = source.clone();
    let budget = MemoryBudget::new(1024 * 1024);
    let mut retained = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = analyze_artifacts_with_memory(
        &source,
        None,
        ArtifactAnalysisOptions::default(),
        &mut retained,
    )?;
    assert_eq!(report.source_sha256, sha256(&original));
    assert_eq!(source, original);
    assert_eq!(
        report.artifacts.first().map(|item| item.bytes.as_slice()),
        Some(original.as_slice())
    );
    assert!(retained.bytes() >= u64::try_from(original.len())?);
    drop(report);
    drop(retained);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
