use super::processing::{PendingCase, RecoveredCase, process_case_batch};
use super::{
    artifact_collection::{
        AddOutcome, ArtifactCollection, ArtifactCoverage, ArtifactLimits, ArtifactProvenance,
        OmissionReason,
    },
    tshark_objects,
};
use crate::workbench::full_source::{
    FlowAnalysisCoverage, FullSourceCoverage, ReconstructionOmissionCoverage, SourceCoverage,
};
use crate::{
    arguments::{ExportOptions, RecoveryOptions, RecoveryProfile},
    export::recovery_cache::RecoveryContext,
};
use l2_workbench::{
    job::{Counter, Job, MemoryBudget, MemoryClass, MemoryError, Phase, PhaseState},
    reconstruction::Limits,
};
use serde_json::Value;
use std::{error::Error, fs, io, io::Write};

type ArtifactFiles = Vec<(String, Vec<u8>)>;

#[path = "case_snapshot.rs"]
mod case_snapshot_tests;
#[path = "processing.rs"]
mod processing_tests;

#[test]
fn recovery_worker_count_sets_the_cpu_bound_before_per_case_memory_admission() {
    assert_eq!(super::processing::recovery_worker_count(Some(3), 8), 3);
    assert_eq!(super::processing::recovery_worker_count(None, 8), 8);
    assert_eq!(super::processing::recovery_worker_count(Some(8), 2), 2);
    assert_eq!(super::processing::recovery_worker_count(None, 0), 1);
}

#[test]
fn collection_jobs_one_and_two_preserve_logical_output() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("flows.pcap");
    fs::write(&capture, two_udp_flows()?)?;

    let single = collect_with_jobs(&capture, temporary.path(), 1)?;
    let parallel = collect_with_jobs(&capture, temporary.path(), 2)?;

    assert_eq!(parallel.source_coverage, single.source_coverage);
    assert_eq!(parallel.recovery_coverage, single.recovery_coverage);
    assert_eq!(parallel.artifact_manifest, single.artifact_manifest);
    assert_eq!(parallel.artifact_files, single.artifact_files);
    Ok(())
}

#[test]
fn collection_preserves_typed_memory_failure_with_capture_context() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("flows.pcap");
    let (error, budget) = collect_with_insufficient_memory(temporary.path(), &capture)?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert!(error.to_string().contains(&capture.display().to_string()));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn collection_error_escapes_capture_path_terminal_controls() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("flow\n\u{1b}[31m.pcap");
    let (error, _) = collect_with_insufficient_memory(temporary.path(), &capture)?;
    let message = error.to_string();
    assert!(message.contains(&capture.display().to_string().escape_debug().to_string()));
    assert!(!message.contains('\n'));
    assert!(!message.contains('\u{1b}'));
    Ok(())
}

#[test]
fn real_recovery_worker_preserves_shared_memory_limit_failure() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("http.pcap");
    fs::write(&capture, four_http_flows()?)?;
    let mut indexed = crate::workbench::full_source::acquire_indexed_source(
        &capture,
        temporary.path(),
        &crate::workbench::full_source::AcquisitionOptions::default(),
    )?;
    let budget = MemoryBudget::new(4 * 1024 * 1024);
    indexed.store.set_memory_budget(budget.clone())?;
    let options = RecoveryOptions {
        profile: RecoveryProfile::Fast,
        ..RecoveryOptions::default()
    };
    let context = RecoveryContext {
        cache: None,
        job: None,
        memory: Some(&budget),
        options: &options,
    };
    let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build()?;
    let mut observed = None;
    let analysis = crate::workbench::full_source::analyze_indexed_source_with_context(
        &indexed.store,
        &indexed.receipt,
        crate::workbench::full_source::IndexedAnalysisOptions {
            limits: Limits::default(),
            include_cohorts: false,
        },
        crate::workbench::full_source::IndexedAnalysisContext::default(),
        |item| {
            let mut batch = vec![PendingCase::new(item)?];
            let snapshot = budget.snapshot()?;
            let remaining = snapshot.limit_bytes - snapshot.used_bytes;
            let held = budget.try_reserve(MemoryClass::Base, remaining)?;
            let error =
                process_case_batch(&mut batch, &pool, temporary.path(), &context, |_| Ok(()))
                    .err()
                    .ok_or("recovery should fail when the shared budget is full")?;
            observed = crate::memory_error::find(error.as_ref());
            drop(held);
            Err(io::Error::other("stop after the first Case").into())
        },
    );
    assert!(analysis.is_err());
    assert!(matches!(observed, Some(MemoryError::Limit { .. })));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

fn collect_with_insufficient_memory(
    directory: &std::path::Path,
    capture: &std::path::Path,
) -> Result<(Box<dyn Error>, MemoryBudget), Box<dyn Error>> {
    let staging = directory.join("staging");
    fs::write(capture, two_udp_flows()?)?;
    fs::create_dir(&staging)?;
    let options = ExportOptions {
        capture: capture.to_owned(),
        output: None,
        require_tshark: false,
        recovery: RecoveryOptions::default(),
    };
    let budget = MemoryBudget::new(1);
    let context = RecoveryContext {
        cache: None,
        job: None,
        memory: Some(&budget),
        options: &options.recovery,
    };
    let error =
        super::collection::collect_export(&staging, &options, ArtifactLimits::default(), &context)
            .err()
            .ok_or("insufficient memory should stop collection")?;
    Ok((error, budget))
}

#[test]
fn collection_phases_cover_indexed_analysis_and_optional_tshark() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("flows.pcap");
    let staging = temporary.path().join("staging");
    fs::write(&capture, two_udp_flows()?)?;
    fs::create_dir(&staging)?;
    let options = ExportOptions {
        capture,
        output: None,
        require_tshark: false,
        recovery: RecoveryOptions {
            profile: RecoveryProfile::Fast,
            jobs: Some(1),
            ..RecoveryOptions::default()
        },
    };
    let job = Job::new("collection phase test");
    let context = RecoveryContext {
        memory: None,
        cache: None,
        job: Some(&job),
        options: &options.recovery,
    };

    let _collected = super::collection::collect_export(
        &staging,
        &options,
        super::artifact_collection::ArtifactLimits::default(),
        &context,
    )?;
    let snapshot = job.snapshot()?;

    for phase in [
        Phase::Ingestion,
        Phase::Reconstruction,
        Phase::NativeExtraction,
        Phase::FramingRecordDiscovery,
        Phase::TransformDiscovery,
        Phase::AssemblyValidation,
        Phase::Expansion,
    ] {
        assert_eq!(
            snapshot.phase(phase).map(|progress| progress.state),
            Some(PhaseState::Completed),
            "phase {phase:?} should finish after collection"
        );
    }
    assert_eq!(snapshot.counters.get(&Counter::Flows), Some(&2));
    Ok(())
}

#[test]
fn one_two_and_four_workers_keep_charged_case_outputs_in_source_order() -> Result<(), Box<dyn Error>>
{
    const MEMORY_BYTES: u64 = 256 * 1024 * 1024;
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("flows.pcap");
    fs::write(&capture, four_http_flows()?)?;

    let single = recover_indexed_cases(&capture, temporary.path(), 1, 1, MEMORY_BYTES)?;
    assert_eq!(single.artifacts.len(), 4);
    for jobs in [2, 4] {
        let parallel = recover_indexed_cases(&capture, temporary.path(), jobs, jobs, MEMORY_BYTES)?;
        assert_eq!(parallel.scopes, single.scopes);
        assert_eq!(parallel.cases, single.cases);
        assert_eq!(parallel.coverage, single.coverage);
        assert_eq!(parallel.source_coverage, single.source_coverage);
        assert_eq!(parallel.artifact_manifest, single.artifact_manifest);
        assert_eq!(parallel.artifacts, single.artifacts);
        assert!(parallel.peak_case_bytes > 0);
        assert_eq!(parallel.remaining_live_bytes, 0);
    }

    assert!(single.peak_case_bytes > 0);
    assert_eq!(single.remaining_live_bytes, 0);
    Ok(())
}

#[test]
fn four_requested_workers_wait_for_case_memory_without_changing_recovered_bytes()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("flows.pcap");
    fs::write(&capture, four_http_flows()?)?;
    let reference = recover_indexed_cases(&capture, temporary.path(), 1, 1, 48 * 1024 * 1024)?;
    let constrained = recover_indexed_cases(&capture, temporary.path(), 4, 4, 48 * 1024 * 1024)?;
    assert_eq!(constrained.scopes, reference.scopes);
    assert_eq!(constrained.cases, reference.cases);
    assert_eq!(constrained.coverage, reference.coverage);
    assert_eq!(constrained.artifacts, reference.artifacts);
    assert_eq!(constrained.working_sets.peak_active_cases, 1);
    assert_eq!(
        constrained.working_sets.admitted_cases,
        u64::try_from(constrained.cases.len())?
    );
    assert!(constrained.working_sets.admission_denials > 0);
    assert_eq!(constrained.working_sets.active_cases, 0);
    assert_eq!(constrained.working_sets.reserved_bytes, 0);
    assert_eq!(constrained.remaining_live_bytes, 0);
    Ok(())
}

#[test]
fn a_batch_larger_than_the_pool_keeps_source_order_and_recovers_identical_artifacts()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("flows.pcap");
    fs::write(&capture, four_http_flows()?)?;
    let reference = recover_indexed_cases(&capture, temporary.path(), 1, 1, 256 * 1024 * 1024)?;
    let queued = recover_indexed_cases(&capture, temporary.path(), 2, 4, 256 * 1024 * 1024)?;
    assert_eq!(queued.scopes, reference.scopes);
    assert_eq!(queued.cases, reference.cases);
    assert_eq!(queued.artifacts, reference.artifacts);
    assert_eq!(queued.coverage, reference.coverage);
    assert!(queued.working_sets.peak_active_cases <= 2);
    assert_eq!(queued.remaining_live_bytes, 0);
    Ok(())
}

struct RecoveredCaseSnapshot {
    scopes: Vec<Value>,
    cases: Vec<Vec<u8>>,
    coverage: Value,
    source_coverage: Value,
    artifact_manifest: Vec<u8>,
    artifacts: ArtifactFiles,
    peak_case_bytes: u64,
    remaining_live_bytes: u64,
    working_sets: l2_workbench::job::WorkingSetSnapshot,
}

fn recover_indexed_cases(
    capture: &std::path::Path,
    temporary_parent: &std::path::Path,
    worker_count: usize,
    batch_length: usize,
    memory_bytes: u64,
) -> Result<RecoveredCaseSnapshot, Box<dyn Error>> {
    let budget = MemoryBudget::new(memory_bytes);
    let options = RecoveryOptions {
        profile: RecoveryProfile::Fast,
        jobs: Some(worker_count),
        memory_limit: memory_bytes,
        ..RecoveryOptions::default()
    };
    let context = RecoveryContext {
        memory: Some(&budget),
        cache: None,
        job: None,
        options: &options,
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(worker_count)
        .build()?;
    let mut scopes = Vec::new();
    let mut cases = Vec::new();
    let mut coverage = super::RecoveryCoverage::default();
    let artifact_directory = tempfile::tempdir_in(temporary_parent)?;
    let mut artifacts =
        ArtifactCollection::new(artifact_directory.path(), ArtifactLimits::default())?;
    let mut batch = Vec::with_capacity(batch_length);
    let mut peak_case_bytes = 0;
    let mut emit = |case: RecoveredCase| {
        collect_test_case(case, &mut artifacts, &mut coverage, &mut scopes, &mut cases)
    };
    let mut indexed = crate::workbench::full_source::acquire_indexed_source(
        capture,
        temporary_parent,
        &crate::workbench::full_source::AcquisitionOptions::default(),
    )?;
    indexed.store.set_memory_budget(budget.clone())?;
    let source = crate::workbench::full_source::analyze_indexed_source_with_context(
        &indexed.store,
        &indexed.receipt,
        crate::workbench::full_source::IndexedAnalysisOptions {
            limits: Limits::default(),
            include_cohorts: true,
        },
        crate::workbench::full_source::IndexedAnalysisContext::default(),
        |item| {
            peak_case_bytes = peak_case_bytes.max(budget.snapshot()?.used(MemoryClass::Case));
            batch.push(PendingCase::new(item)?);
            if batch.len() == batch_length {
                process_case_batch(&mut batch, &pool, temporary_parent, &context, &mut emit)?;
            }
            Ok(())
        },
    )?;
    process_case_batch(&mut batch, &pool, temporary_parent, &context, &mut emit)?;
    let buffered = budget.snapshot()?.buffered_cases;
    assert_eq!(buffered.completed_waits, u64::try_from(cases.len())?);
    assert_eq!(buffered.current_cases, 0);
    assert_eq!(buffered.current_charged_bytes, 0);
    assert!(buffered.peak_charged_bytes > 0);
    let (artifact_manifest, artifacts) =
        artifact_snapshot(&mut artifacts, artifact_directory.path())?;
    Ok(RecoveredCaseSnapshot {
        scopes,
        cases,
        coverage: serde_json::to_value(coverage)?,
        source_coverage: serde_json::to_value(&source.source)?,
        artifact_manifest,
        artifacts,
        peak_case_bytes,
        remaining_live_bytes: budget.snapshot()?.used_bytes,
        working_sets: budget.snapshot()?.working_sets,
    })
}

fn collect_test_case(
    recovered: RecoveredCase,
    artifacts: &mut ArtifactCollection,
    coverage: &mut super::RecoveryCoverage,
    scopes: &mut Vec<Value>,
    cases: &mut Vec<Vec<u8>>,
) -> Result<(), Box<dyn Error>> {
    let RecoveredCase {
        item,
        scope,
        recovery,
    } = recovered;
    let mut encoded = Vec::new();
    match item {
        crate::workbench::full_source::FullSourceItem::Flow(analysis) => {
            collect_test_flow_artifacts(artifacts, &analysis.result.case, &analysis.flow, &scope)?;
            analysis.result.case.write_json(&mut encoded)?;
        }
        crate::workbench::full_source::FullSourceItem::FlowPage(page) => {
            collect_test_flow_artifacts(artifacts, &page.result.case, &page.flow, &scope)?;
            page.result.case.write_json(&mut encoded)?;
        }
        crate::workbench::full_source::FullSourceItem::Cohort(cohort) => {
            super::collection::collect_cohort_artifacts(artifacts, &cohort, None, &scope)?;
            cohort.result.case.write_json(&mut encoded)?;
        }
    }
    coverage.merge(&recovery.coverage)?;
    scopes.push(scope);
    cases.push(encoded);
    Ok(())
}

fn collect_test_flow_artifacts(
    artifacts: &mut ArtifactCollection,
    case: &l2_workbench::evidence::Case,
    flow: &l2_workbench::store::Flow,
    scope: &Value,
) -> Result<(), Box<dyn Error>> {
    let flow = serde_json::to_value(flow)?;
    let context = super::provenance::ArtifactSourceContext {
        flow: Some(flow.clone()),
        supporting_flows: vec![flow],
        cohort_scope: None,
        case_id: None,
        case_scope: scope.clone(),
    };
    super::collection::collect_case_artifacts_with_context(artifacts, case, |_, _| {
        Ok(context.clone())
    })
}

struct CollectionSnapshot {
    source_coverage: Value,
    recovery_coverage: Value,
    artifact_manifest: Vec<u8>,
    artifact_files: ArtifactFiles,
}

fn collect_with_jobs(
    capture: &std::path::Path,
    temporary_parent: &std::path::Path,
    jobs: usize,
) -> Result<CollectionSnapshot, Box<dyn Error>> {
    let staging = tempfile::tempdir_in(temporary_parent)?;
    let options = ExportOptions {
        capture: capture.to_owned(),
        output: None,
        require_tshark: false,
        recovery: RecoveryOptions {
            profile: RecoveryProfile::Fast,
            jobs: Some(jobs),
            ..RecoveryOptions::default()
        },
    };
    let context = RecoveryContext {
        memory: None,
        cache: None,
        job: None,
        options: &options.recovery,
    };
    let mut collected = super::collection::collect_export(
        staging.path(),
        &options,
        super::artifact_collection::ArtifactLimits::default(),
        &context,
    )?;
    let (artifact_manifest, artifact_files) =
        artifact_snapshot(&mut collected.artifacts, staging.path())?;

    Ok(CollectionSnapshot {
        source_coverage: serde_json::to_value(&collected.coverage.source)?,
        recovery_coverage: serde_json::to_value(collected.recovery)?,
        artifact_manifest,
        artifact_files,
    })
}

fn artifact_snapshot(
    collection: &mut ArtifactCollection,
    directory: &std::path::Path,
) -> Result<(Vec<u8>, ArtifactFiles), Box<dyn Error>> {
    let mut manifest = Vec::new();
    collection.write_manifest_artifacts(&mut manifest)?;
    let mut names = collection.file_names()?.into_iter().collect::<Vec<_>>();
    names.sort();
    let files = names
        .into_iter()
        .map(|name| {
            let display = name.to_string_lossy().into_owned();
            Ok((display, fs::read(directory.join(name))?))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    Ok((manifest, files))
}

#[test]
fn rejects_unsafe_flat_file_names() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut collection = ArtifactCollection::new(temporary.path(), ArtifactLimits::default())?;

    for name in ["", ".", "..", "nested/name", r"nested\name", "bad\nname"] {
        let error = collection
            .add_bytes(b"object", name, &provenance())
            .err()
            .ok_or("unsafe artifact name should be rejected")?;
        let error = error
            .downcast_ref::<io::Error>()
            .ok_or("artifact name error is not an io::Error")?;

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "artifact file name must be a safe flat name"
        );
    }
    Ok(())
}

#[test]
fn digest_collision_keeps_bytes_distinct() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut collection = ArtifactCollection::new(temporary.path(), ArtifactLimits::default())?;
    let forced_digest = "a".repeat(64);

    assert_eq!(
        collection.add_bytes_with_digest(b"one", &forced_digest, "first.bin", &provenance())?,
        AddOutcome::Stored
    );
    assert_eq!(
        collection.add_bytes_with_digest(b"two", &forced_digest, "second.bin", &provenance())?,
        AddOutcome::Stored
    );

    assert_eq!(collection.coverage().unique_artifacts_retained, 2);
    let names = collection.file_names()?;
    assert_eq!(names.len(), 2);
    let contents = names
        .iter()
        .map(|name| fs::read(temporary.path().join(name)))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(contents.contains(&b"one".to_vec()));
    assert!(contents.contains(&b"two".to_vec()));
    Ok(())
}

#[test]
fn same_origin_is_suppressed() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut collection = ArtifactCollection::new(temporary.path(), ArtifactLimits::default())?;

    assert_eq!(
        collection.add_bytes(b"same bytes", "first.bin", &provenance())?,
        AddOutcome::Stored
    );
    assert_eq!(
        collection.add_bytes(b"same bytes", "second.bin", &provenance())?,
        AddOutcome::SameOrigin
    );

    let coverage = collection.coverage();
    assert_eq!(coverage.references_selected, 2);
    assert_eq!(coverage.references_retained, 1);
    assert_eq!(coverage.references_omitted, 0);
    assert_eq!(coverage.same_origin_references_suppressed, 1);
    assert_eq!(coverage.duplicate_byte_references_grouped, 0);
    assert_eq!(collection.file_names()?.len(), 1);
    Ok(())
}

#[test]
fn exact_limit_keeps_source_complete() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("flows.pcap");
    let staging = temporary.path().join("staging");
    fs::create_dir(&staging)?;
    let bytes = two_udp_flows()?;
    fs::write(&capture, &bytes)?;
    let limits = ArtifactLimits {
        artifacts: 1,
        artifact_bytes: 3,
        provenance_entries: 8,
        provenance_bytes: 16 * 1024,
        evidence_bytes: 1024 * 1024,
    };
    let mut collection = ArtifactCollection::new(&staging, limits)?;
    let mut visited_flows = 0_usize;

    let source = crate::workbench::full_source::acquire_full_source_in(
        &capture,
        &staging,
        Limits::default(),
        |_analysis| {
            let (name, body) = match visited_flows {
                0 => ("first.bin", b"one".as_slice()),
                1 => ("second.bin", b"two".as_slice()),
                _ => return Err("source visitor received an unexpected flow".into()),
            };
            let outcome = collection.add_bytes(body, name, &provenance())?;
            if visited_flows == 0 && outcome != AddOutcome::Stored {
                return Err("exact-boundary artifact was not retained".into());
            }
            if visited_flows == 1 && outcome != AddOutcome::Omitted(OmissionReason::ArtifactCount) {
                return Err("artifact beyond count limit was not reported".into());
            }
            visited_flows += 1;
            Ok(())
        },
    )?;

    assert_eq!(source.source.bytes, u64::try_from(bytes.len())?);
    assert_eq!(source.source.packet_records, 2);
    assert_eq!(source.analysis.flows, 2);
    assert_eq!(source.analysis.incomplete_flows, 0);
    assert_eq!(visited_flows, 2);
    let coverage = collection.coverage();
    assert_eq!(coverage.references_selected, 2);
    assert_eq!(coverage.references_retained, 1);
    assert_eq!(coverage.references_omitted, 1);
    assert_eq!(coverage.unique_artifacts_retained, 1);
    assert_eq!(coverage.artifact_bytes_retained, 3);
    assert_eq!(coverage.count_limit_omissions, 1);
    Ok(())
}

#[test]
fn manifest_preserves_artifact_order_and_content_hashes() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut collection = ArtifactCollection::new(temporary.path(), ArtifactLimits::default())?;
    collection.add_bytes(b"first", "one.bin", &provenance())?;
    collection.add_bytes(b"second", "two.bin", &provenance())?;
    let mut manifest = Vec::new();
    collection.write_manifest_artifacts(&mut manifest)?;

    let encoded = format!("[{}]", String::from_utf8(manifest)?);
    let entries: Value = serde_json::from_str(&encoded)?;
    let first = entries
        .as_array()
        .and_then(|items| items.first())
        .ok_or("first artifact manifest entry is missing")?;
    let second = entries
        .as_array()
        .and_then(|items| items.get(1))
        .ok_or("second artifact manifest entry is missing")?;
    assert_eq!(
        first.get("file"),
        Some(&Value::String(String::from("one.bin")))
    );
    assert_eq!(
        second.get("file"),
        Some(&Value::String(String::from("two.bin")))
    );
    for (entry, bytes) in [(first, b"first".as_slice()), (second, b"second".as_slice())] {
        assert_eq!(
            entry.get("sha256").and_then(Value::as_str),
            Some(l2_workbench::sha256(bytes).as_str()),
            "the manifest must retain the digest of each published artifact"
        );
    }
    assert_eq!(
        first
            .get("provenance")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    Ok(())
}

#[test]
fn omitted_archive_member_identity_is_bounded_and_published() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut collection = archive_omission_collection(temporary.path())?;
    assert_omitted_archive_member_manifest(&mut collection)?;
    assert_omission_manifest_and_limitations(temporary.path(), &mut collection)?;
    Ok(())
}

fn archive_omission_collection(
    staging: &std::path::Path,
) -> Result<ArtifactCollection, Box<dyn Error>> {
    let mut collection = ArtifactCollection::new(
        staging,
        ArtifactLimits {
            artifacts: 1,
            artifact_bytes: 1024,
            provenance_entries: 1,
            provenance_bytes: 16 * 1024,
            evidence_bytes: 1024 * 1024,
        },
    )?;
    assert_eq!(
        collection.add_bytes(b"retained", "retained.bin", &provenance())?,
        AddOutcome::Stored
    );
    let mut archive_member = provenance();
    archive_member.category = String::from("recovered_artifact");
    archive_member.case_id = Some(String::from("case-17"));
    archive_member.selected_node_id = Some(41);
    archive_member.validation_node_id = Some(42);
    archive_member.extension_node_id = Some(43);
    archive_member.selection = Some(serde_json::json!({
        "archive_path": "outer.zip/folder/member.bin",
        "selected_file_name": "member.bin",
        "archive_parent": { "node_id": 39 }
    }));
    assert_eq!(
        collection.add_bytes(b"omitted", "member.bin", &archive_member)?,
        AddOutcome::Omitted(OmissionReason::ProvenanceCount)
    );
    archive_member.selected_node_id = Some(44);
    archive_member.selection = Some(serde_json::json!({
        "archive_path": "outer.zip/folder/second.bin",
        "selected_file_name": "second.bin"
    }));
    assert_eq!(
        collection.add_bytes(b"also omitted", "second.bin", &archive_member)?,
        AddOutcome::Omitted(OmissionReason::ProvenanceCount)
    );
    Ok(collection)
}

fn assert_omitted_archive_member_manifest(
    collection: &mut ArtifactCollection,
) -> Result<(), Box<dyn Error>> {
    let mut encoded = Vec::new();
    collection.write_manifest_omissions(&mut encoded)?;
    let manifest: Value = serde_json::from_slice(&encoded)?;
    assert_json_field(&manifest, "details_retained", &serde_json::json!(1))?;
    assert_json_field(&manifest, "details_not_retained", &serde_json::json!(1))?;
    assert_json_field(&manifest, "unidentified", &serde_json::json!(0))?;
    let detail = manifest
        .get("details")
        .and_then(Value::as_array)
        .and_then(|details| details.first())
        .ok_or("omitted archive member detail is missing")?;
    for (key, expected) in [
        ("reason", serde_json::json!("provenance_count_limit")),
        ("bytes", serde_json::json!(7)),
        ("category", serde_json::json!("recovered_artifact")),
        ("case_id", serde_json::json!("case-17")),
        ("selected_node_id", serde_json::json!(41)),
        ("validation_node_id", serde_json::json!(42)),
        ("extension_node_id", serde_json::json!(43)),
        ("archive_parent_node_id", serde_json::json!(39)),
        (
            "archive_path",
            serde_json::json!("outer.zip/folder/member.bin"),
        ),
        ("selected_file_name", serde_json::json!("member.bin")),
    ] {
        assert_json_field(detail, key, &expected)?;
    }
    Ok(())
}

fn assert_omission_manifest_and_limitations(
    staging: &std::path::Path,
    collection: &mut ArtifactCollection,
) -> Result<(), Box<dyn Error>> {
    let full_source = empty_full_source();
    let limits = ArtifactLimits {
        artifacts: 1,
        artifact_bytes: 1024,
        provenance_entries: 1,
        provenance_bytes: 16 * 1024,
        evidence_bytes: 1024 * 1024,
    };
    let discovery = super::discovery_coverage(
        &full_source,
        collection.coverage(),
        limits,
        &super::RecoveryCoverage::default(),
        true,
        super::EvidenceCoverage::default(),
    );
    let capture = staging.join("capture.pcap");
    let completion = super::ExportCompletion {
        tshark_required: false,
        complete: false,
        incomplete_components: Vec::new(),
    };
    let mut limitations = super::LimitationSpool::new(staging)?;
    let tshark = tshark_objects::Collection::default();
    let mut summary = super::Summary {
        capture: &capture,
        completion: &completion,
        coverage: &full_source,
        discovery,
        artifacts: collection,
        evidence: super::EvidenceCoverage::default(),
        tshark: &tshark,
        tshark_error: None,
        limitations: &mut limitations,
    };
    super::write_manifest(staging, &mut summary)?;
    let full_manifest: Value = serde_json::from_slice(&fs::read(staging.join("manifest.json"))?)?;
    let omission_manifest = full_manifest
        .get("omitted_artifact_references")
        .ok_or("omitted artifact manifest section is missing")?;
    assert_json_field(omission_manifest, "details_retained", &serde_json::json!(1))?;
    assert_json_field(
        omission_manifest,
        "details_not_retained",
        &serde_json::json!(1),
    )?;

    let limitations_path = staging.join("artifact-limitations.txt");
    let mut rendered = fs::File::create(&limitations_path)?;
    super::write_artifact_limitations(&mut rendered, &summary)?;
    drop(rendered);
    let rendered = fs::read_to_string(limitations_path)?;
    assert!(rendered.contains("Omission details: 1 retained in manifest; 1 exceeded the detail bound; 0 unidentified TShark omissions"), "{rendered}");
    Ok(())
}

fn assert_json_field(value: &Value, key: &str, expected: &Value) -> Result<(), Box<dyn Error>> {
    let actual = value.get(key).ok_or("expected manifest field is missing")?;
    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn omission_detail_byte_limit_counts_unretained_identity() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut collection = ArtifactCollection::new(
        temporary.path(),
        ArtifactLimits {
            artifacts: 1,
            artifact_bytes: 16,
            provenance_entries: 4,
            provenance_bytes: 1,
            evidence_bytes: 1024,
        },
    )?;

    assert_eq!(
        collection.add_bytes(b"payload", "payload.bin", &provenance())?,
        AddOutcome::Omitted(OmissionReason::ProvenanceBytes)
    );
    let coverage = collection.coverage();
    assert_eq!(coverage.omission_details_retained, 0);
    assert_eq!(coverage.omission_details_not_retained, 1);
    assert_eq!(coverage.omission_detail_bytes_retained, 0);
    assert_eq!(coverage.unidentified_omissions, 0);

    let mut manifest = Vec::new();
    collection.write_manifest_omissions(&mut manifest)?;
    let manifest: Value = serde_json::from_slice(&manifest)?;
    assert_eq!(
        manifest
            .get("details")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    assert_json_field(&manifest, "details_not_retained", &serde_json::json!(1))?;
    Ok(())
}

#[test]
fn anonymous_bulk_omissions_are_counted_without_details() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut collection = ArtifactCollection::new(temporary.path(), ArtifactLimits::default())?;

    collection.record_omissions(OmissionReason::ProvenanceCount, 3, 24)?;

    let coverage = collection.coverage();
    assert_eq!(coverage.references_selected, 3);
    assert_eq!(coverage.references_omitted, 3);
    assert_eq!(coverage.unidentified_omissions, 3);
    assert_eq!(coverage.omission_details_retained, 0);
    assert_eq!(coverage.omission_details_not_retained, 0);
    let mut manifest = Vec::new();
    collection.write_manifest_omissions(&mut manifest)?;
    let manifest: Value = serde_json::from_slice(&manifest)?;
    assert_eq!(
        manifest
            .get("details")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    assert_json_field(&manifest, "unidentified", &serde_json::json!(3))?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn tshark_limit_marks_partial() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let staging = temporary.path().join("staging");
    let object_directory = temporary.path().join("tshark-http");
    fs::create_dir(&staging)?;
    fs::create_dir(&object_directory)?;
    fs::write(object_directory.join("object"), b"larger than budget")?;
    let limits = ArtifactLimits {
        artifacts: 2,
        artifact_bytes: 3,
        provenance_entries: 8,
        provenance_bytes: 16 * 1024,
        evidence_bytes: 1024 * 1024,
    };
    let mut artifacts = ArtifactCollection::new(&staging, limits)?;
    assert_eq!(
        artifacts.add_bytes(b"one", "native.bin", &provenance())?,
        AddOutcome::Stored
    );

    let tshark = tshark_objects::collect(
        &[(String::from("http"), object_directory)],
        &mut artifacts,
        10,
    )?;

    assert_eq!(tshark.objects_exported, 0);
    assert_eq!(tshark.skipped, 1);
    assert_eq!(tshark.unsafe_entries_skipped, 0);
    assert_eq!(artifacts.coverage().references_selected, 2);
    assert_eq!(artifacts.coverage().references_retained, 1);
    assert_eq!(artifacts.coverage().references_omitted, 1);
    assert_eq!(artifacts.coverage().omission_details_retained, 1);
    assert_eq!(artifacts.coverage().unidentified_omissions, 0);
    assert_eq!(artifacts.coverage().artifact_byte_limit_omissions, 1);
    let full_source = empty_full_source();
    let discovery = super::discovery_coverage(
        &full_source,
        artifacts.coverage(),
        limits,
        &super::RecoveryCoverage::default(),
        false,
        super::EvidenceCoverage::default(),
    );
    assert_eq!(discovery.status, "partial");
    Ok(())
}

#[test]
fn evidence_case_omission_marks_discovery_partial() {
    let full_source = empty_full_source();
    let discovery = super::discovery_coverage(
        &full_source,
        ArtifactCoverage::default(),
        ArtifactLimits::default(),
        &super::RecoveryCoverage::default(),
        true,
        super::EvidenceCoverage {
            selected_cases: 1,
            omitted_cases: 1,
            omitted_bytes: 12,
            budget_bytes: 1,
            ..super::EvidenceCoverage::default()
        },
    );

    assert_eq!(discovery.status, "partial");
}

#[cfg(unix)]
#[test]
fn tshark_scan_budget_accepts_exact_entry_count() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let staging = temporary.path().join("staging");
    let object_directory = temporary.path().join("tshark-http");
    fs::create_dir(&staging)?;
    fs::create_dir(&object_directory)?;
    fs::write(object_directory.join("object"), b"payload")?;
    let mut artifacts = ArtifactCollection::new(&staging, ArtifactLimits::default())?;

    let tshark = tshark_objects::collect(
        &[(String::from("http"), object_directory)],
        &mut artifacts,
        1,
    )?;

    assert_eq!(tshark.scan_entries, 1);
    assert!(!tshark.scan_limit_reached);
    assert_eq!(tshark.objects_exported, 1);
    Ok(())
}

#[cfg(unix)]
#[test]
fn tshark_duplicate_summary_shows_protocol_and_shared_artifact() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let staging = temporary.path().join("staging");
    let object_directory = temporary.path().join("tshark-http");
    fs::create_dir(&staging)?;
    fs::create_dir(&object_directory)?;
    fs::write(object_directory.join("object"), b"same artifact")?;
    let mut artifacts = ArtifactCollection::new(&staging, ArtifactLimits::default())?;
    let recovered = ArtifactProvenance {
        category: String::from("recovered_artifact"),
        case_id: None,
        selected_node_id: None,
        validation_node_id: None,
        extension_node_id: None,
        flow: None,
        supporting_flows: Vec::new(),
        cohort_scope: None,
        node: None,
        description: Some(String::from("recovered object")),
        selection: None,
        signature_candidates: Vec::new(),
        source_ranges: Vec::new(),
        canonical_origin: serde_json::json!({ "category": "recovered_artifact", "node": 1 }),
    };
    artifacts.add_bytes(b"same artifact", "recovered.bin", &recovered)?;

    let tshark = tshark_objects::collect(
        &[(String::from("http"), object_directory)],
        &mut artifacts,
        10,
    )?;

    assert_eq!(tshark.objects_exported, 0);
    assert_eq!(tshark.duplicates, 1);
    assert_eq!(artifacts.coverage().tshark_object_references_retained, 1);
    assert_eq!(artifacts.file_names()?.len(), 1);

    let full_source = empty_full_source();
    let limits = ArtifactLimits::default();
    let discovery = super::discovery_coverage(
        &full_source,
        artifacts.coverage(),
        limits,
        &super::RecoveryCoverage::default(),
        true,
        super::EvidenceCoverage::default(),
    );
    let capture = temporary.path().join("capture.pcap");
    let mut limitations = super::LimitationSpool::new(&staging)?;
    let completion = super::ExportCompletion {
        tshark_required: false,
        complete: true,
        incomplete_components: Vec::new(),
    };
    let mut summary = super::Summary {
        capture: &capture,
        completion: &completion,
        coverage: &full_source,
        discovery,
        artifacts: &mut artifacts,
        evidence: super::EvidenceCoverage::default(),
        tshark: &tshark,
        tshark_error: None,
        limitations: &mut limitations,
    };
    let summary_path = staging.join("summary.txt");
    let mut output = fs::File::create(&summary_path)?;

    super::write_tshark_contents(&mut output, &mut summary)?;
    drop(output);

    let rendered = fs::read_to_string(summary_path)?;
    assert!(
        rendered.contains(
            "TShark object observations (including exact-byte duplicates linked to existing artifacts):"
        ),
        "{rendered}"
    );
    assert!(rendered.contains("recovered.bin"), "{rendered}");
    assert!(rendered.contains("Protocol: http"), "{rendered}");
    assert!(!rendered.contains("sha256"), "{rendered}");
    assert!(!rendered.contains("{\""), "{rendered}");
    assert_eq!(artifacts.file_names()?.len(), 1);
    Ok(())
}

#[cfg(unix)]
#[test]
fn tshark_scan_budget_stops_after_first_over_budget_entry() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let staging = temporary.path().join("staging");
    let object_directory = temporary.path().join("tshark-http");
    fs::create_dir(&staging)?;
    fs::create_dir(&object_directory)?;
    fs::write(object_directory.join("one"), b"first")?;
    fs::write(object_directory.join("two"), b"second")?;
    let mut artifacts = ArtifactCollection::new(&staging, ArtifactLimits::default())?;

    let tshark = tshark_objects::collect(
        &[(String::from("http"), object_directory)],
        &mut artifacts,
        1,
    )?;

    assert_eq!(tshark.scan_entries, 2);
    assert!(tshark.scan_limit_reached);
    assert_eq!(tshark.objects_exported, 1);
    assert_eq!(tshark.issues.len(), 1);
    assert!(
        tshark
            .issues
            .first()
            .is_some_and(|issue| issue.contains("remaining entries"))
    );
    Ok(())
}

fn provenance() -> ArtifactProvenance {
    ArtifactProvenance {
        category: String::from("test"),
        case_id: None,
        selected_node_id: None,
        validation_node_id: None,
        extension_node_id: None,
        flow: None,
        supporting_flows: Vec::new(),
        cohort_scope: None,
        node: None,
        description: None,
        selection: None,
        signature_candidates: Vec::new(),
        source_ranges: Vec::new(),
        canonical_origin: serde_json::json!({ "category": "test" }),
    }
}

fn empty_full_source() -> FullSourceCoverage {
    FullSourceCoverage {
        source: SourceCoverage {
            source_id: String::from("sha256:synthetic"),
            bytes: 0,
            packet_records: 0,
            supported_transport_records: 0,
            packets_without_supported_transport: 0,
            collection_summary: l2_pcap::CollectionSummary::default(),
        },
        analysis: FlowAnalysisCoverage::default(),
        cohort_reconstruction: ReconstructionOmissionCoverage::default(),
        cohort_analysis: None,
    }
}

fn two_udp_flows() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut capture = capture_header();
    append_udp_record(&mut capture, 40_000, b"a")?;
    append_udp_record(&mut capture, 40_001, b"b")?;
    Ok(capture)
}

fn capture_header() -> Vec<u8> {
    let mut capture = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    capture.extend_from_slice(&[0; 8]);
    capture.extend_from_slice(&65_535_u32.to_le_bytes());
    capture.extend_from_slice(&1_u32.to_le_bytes());
    capture
}

fn four_http_flows() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut capture = capture_header();
    for index in 0_u16..4 {
        let port = 40_000 + index;
        let body = format!("synthetic-body-{index}");
        let payload = format!(
            "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        append_tcp_record(&mut capture, port, 100, 0x02, b"")?;
        append_tcp_record(&mut capture, port, 101, 0x18, payload.as_bytes())?;
    }
    Ok(capture)
}

fn append_tcp_record(
    capture: &mut Vec<u8>,
    source_port: u16,
    sequence: u32,
    flags: u8,
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    let ip_length = 40_u16
        .checked_add(u16::try_from(payload.len())?)
        .ok_or("TCP frame is too large")?;
    let mut frame = vec![0_u8; 54];
    write_frame_bytes(&mut frame, 12, &0x0800_u16.to_be_bytes())?;
    write_frame_byte(&mut frame, 14, 0x45)?;
    write_frame_bytes(&mut frame, 16, &ip_length.to_be_bytes())?;
    write_frame_byte(&mut frame, 22, 64)?;
    write_frame_byte(&mut frame, 23, 6)?;
    write_frame_bytes(&mut frame, 26, &[192, 0, 2, 1])?;
    write_frame_bytes(&mut frame, 30, &[198, 51, 100, 2])?;
    write_frame_bytes(&mut frame, 34, &source_port.to_be_bytes())?;
    write_frame_bytes(&mut frame, 36, &80_u16.to_be_bytes())?;
    write_frame_bytes(&mut frame, 38, &sequence.to_be_bytes())?;
    write_frame_byte(&mut frame, 46, 0x50)?;
    write_frame_byte(&mut frame, 47, flags)?;
    frame.extend_from_slice(payload);
    append_capture_frame(capture, &frame)
}

fn append_udp_record(
    capture: &mut Vec<u8>,
    source_port: u16,
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    let payload_length = u16::try_from(payload.len())?;
    let udp_length = 8_u16
        .checked_add(payload_length)
        .ok_or("UDP length overflow")?;
    let ip_length = 20_u16
        .checked_add(udp_length)
        .ok_or("IPv4 length overflow")?;
    let mut frame = vec![0_u8; 42];
    write_frame_bytes(&mut frame, 12, &0x0800_u16.to_be_bytes())?;
    write_frame_byte(&mut frame, 14, 0x45)?;
    write_frame_bytes(&mut frame, 16, &ip_length.to_be_bytes())?;
    write_frame_bytes(&mut frame, 18, &source_port.to_be_bytes())?;
    write_frame_byte(&mut frame, 22, 64)?;
    write_frame_byte(&mut frame, 23, 17)?;
    write_frame_bytes(&mut frame, 26, &[192, 0, 2, 1])?;
    write_frame_bytes(&mut frame, 30, &[198, 51, 100, 2])?;
    write_frame_bytes(&mut frame, 34, &source_port.to_be_bytes())?;
    write_frame_bytes(&mut frame, 36, &53_u16.to_be_bytes())?;
    write_frame_bytes(&mut frame, 38, &udp_length.to_be_bytes())?;
    frame.truncate(42);
    frame.extend_from_slice(payload);
    append_capture_frame(capture, &frame)
}

fn append_capture_frame(capture: &mut Vec<u8>, frame: &[u8]) -> Result<(), Box<dyn Error>> {
    let length = u32::try_from(frame.len())?;
    capture.write_all(&1_u32.to_le_bytes())?;
    capture.write_all(&0_u32.to_le_bytes())?;
    capture.write_all(&length.to_le_bytes())?;
    capture.write_all(&length.to_le_bytes())?;
    capture.write_all(frame)?;
    Ok(())
}

fn write_frame_byte(frame: &mut [u8], offset: usize, value: u8) -> Result<(), Box<dyn Error>> {
    *frame
        .get_mut(offset)
        .ok_or("synthetic frame field is out of range")? = value;
    Ok(())
}

fn write_frame_bytes(frame: &mut [u8], offset: usize, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or("synthetic frame range overflow")?;
    frame
        .get_mut(offset..end)
        .ok_or("synthetic frame field is out of range")?
        .copy_from_slice(bytes);
    Ok(())
}
