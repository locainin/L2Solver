use super::{StreamingBudget, observation_work};
use l2_workbench::{
    derivation::Operation,
    job::{Job, MemoryBudget},
    recovery::proposals::transform_proposal_scan_work_bound,
};
use std::error::Error;

#[test]
fn stream_queue_admits_replacement_while_the_old_buffer_is_live() -> Result<(), Box<dyn Error>> {
    use super::super::{ObservingReader, StreamObject, StreamQueue};
    use crate::refine::file_artifact::DerivedFile;
    use l2_workbench::job::MemoryClass;

    let size = std::mem::size_of::<StreamObject>();
    let memory = MemoryBudget::new(u64::try_from(12 * size - 1)?);
    let mut queue = StreamQueue::new(&memory)?;
    for _ in 0..4 {
        let observation = ObservingReader::new(b"".as_slice(), true)
            .finish()
            .ok_or("observation missing")?;
        let derived = DerivedFile::new(
            tempfile::tempfile()?,
            memory.try_reserve(MemoryClass::Executor, 0)?,
            Vec::new(),
        );
        queue.push(StreamObject {
            observation,
            derived,
        })?;
    }
    let before = memory.snapshot()?.used_bytes;
    let observation = ObservingReader::new(b"".as_slice(), true)
        .finish()
        .ok_or("observation missing")?;
    let derived = DerivedFile::new(
        tempfile::tempfile()?,
        memory.try_reserve(MemoryClass::Executor, 0)?,
        Vec::new(),
    );
    let error = queue
        .push(StreamObject {
            observation,
            derived,
        })
        .err()
        .ok_or("queue replacement bypassed admission")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(l2_workbench::job::MemoryError::Limit { .. })
    ));
    assert_eq!(queue.values.len(), 4);
    assert_eq!(memory.snapshot()?.used_bytes, before);
    drop(queue);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn stream_reservation_covers_syntax_proposal_and_output_observation_work()
-> Result<(), Box<dyn Error>> {
    let mut budget = StreamingBudget {
        work: 57,
        output: 10,
        zip: 10,
        attempts: 1,
    };
    let reservation = budget
        .reserve(8, &Operation::HexDecode {})
        .ok_or("reservation missing")?;
    let proposal =
        transform_proposal_scan_work_bound(reservation.output).ok_or("proposal work overflow")?;
    let required = reservation.base + reservation.output * 4 + proposal;
    assert!(
        reservation.work >= required,
        "reserved {} but need {required}",
        reservation.work
    );
    Ok(())
}

#[test]
fn stream_reservation_admits_a_small_output_when_the_maximum_would_not_fit()
-> Result<(), Box<dyn Error>> {
    let mut budget = StreamingBudget {
        work: 30,
        output: 4,
        zip: 0,
        attempts: 1,
    };
    let reservation = budget
        .reserve(8, &Operation::HexDecode {})
        .ok_or("a smaller bounded output should fit")?;
    assert_eq!(reservation.output, 1);
    assert_eq!(reservation.work, 29);
    assert_eq!(budget.work, 1);
    Ok(())
}

#[test]
fn queued_stream_metadata_requires_and_releases_shared_memory() -> Result<(), Box<dyn Error>> {
    use super::super::reserve_stream_object;
    use crate::refine::file_artifact::STREAM_METADATA_BYTES;
    use l2_workbench::job::{MemoryBudget, MemoryError};
    let small = MemoryBudget::new(STREAM_METADATA_BYTES - 1);
    assert!(matches!(
        reserve_stream_object(&small),
        Err(MemoryError::Limit { .. })
    ));
    let budget = MemoryBudget::new(STREAM_METADATA_BYTES);
    let lease = reserve_stream_object(&budget)?;
    assert_eq!(budget.snapshot()?.used_bytes, STREAM_METADATA_BYTES);
    drop(lease);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn streaming_omissions_require_memory_before_allocation() -> Result<(), Box<dyn Error>> {
    use super::super::omit;
    use l2_workbench::job::{MemoryClass, MemoryError};

    let memory = MemoryBudget::new(1024 * 1024);
    let job = Job::new("stream omission memory");
    let mut budget = StreamingBudget {
        work: 100_000,
        output: 100_000,
        zip: 0,
        attempts: 1,
    };
    with_stream_source(b"source bytes", &job, &memory, &mut budget, |context| {
        let available = memory.snapshot()?.limit_bytes - memory.snapshot()?.used_bytes;
        let competing = memory.try_reserve(MemoryClass::Cache, available)?;
        let error = omit(context, None, "stream omission needs memory")
            .err()
            .ok_or("omission allocation ignored memory pressure")?;
        assert!(matches!(
            error.downcast_ref::<MemoryError>(),
            Some(MemoryError::Limit { .. })
        ));
        assert_eq!(context.report.omissions.len(), 0);
        drop(competing);

        for _ in 0..100 {
            omit(context, None, "stream omission needs memory")?;
        }
        let records = context.report.omissions.capacity()
            * std::mem::size_of::<l2_workbench::artifact::AnalysisOmission>();
        let messages = context
            .report
            .omissions
            .iter()
            .map(|omission| match omission {
                l2_workbench::artifact::AnalysisOmission::SourceStreamTransform {
                    reason, ..
                } => reason.capacity(),
                _ => 0,
            })
            .sum::<usize>();
        assert!(context.omission_memory.bytes() >= u64::try_from(records + messages)?);
        Ok(())
    })?;
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn formatted_omission_requires_memory_before_growing_its_message() -> Result<(), Box<dyn Error>> {
    use l2_workbench::job::{MemoryClass, MemoryError};

    let memory = MemoryBudget::new(128);
    let mut lease = memory.try_reserve(MemoryClass::Executor, 0)?;
    let error = crate::refine::analysis_memory::format_message(
        format_args!("archive entry {} failed", "x".repeat(256)),
        &mut lease,
    )
    .err()
    .ok_or("formatted message ignored memory pressure")?;
    assert!(matches!(
        error.downcast_ref::<MemoryError>(),
        Some(MemoryError::Limit { .. })
    ));
    drop(lease);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn long_optional_gzip_header_reports_bounded_observation() -> Result<(), Box<dyn Error>> {
    use super::super::ObservingReader;
    use flate2::{Compression, GzBuilder};
    use l2_workbench::recovery::proposals::{TransformProposalBudget, propose_transforms};
    use std::io::{Read, Write};

    let mut encoder = GzBuilder::new()
        .extra(vec![0xa5; 5000])
        .write(Vec::new(), Compression::fast());
    encoder.write_all(b"a valid gzip payload")?;
    let gzip = encoder.finish()?;
    let proposals = propose_transforms(
        &gzip,
        TransformProposalBudget {
            max_candidates: 7,
            max_reports: 0,
        },
    );
    assert!(
        proposals.proposals.iter().any(|proposal| {
            proposal.recipe.steps.first() == Some(&Operation::GzipDecompress {})
        })
    );
    let mut observed = ObservingReader::new(gzip.as_slice(), true);
    std::io::copy(&mut observed, &mut std::io::sink())?;
    let observation = observed.finish().ok_or("observation missing")?;
    let operations = observation.operations()?;
    assert!(!operations.contains(&Operation::GzipDecompress {}));
    assert!(observation.gzip_header_observation_limited(&operations));
    let mut inflater = flate2::read::GzDecoder::new(gzip.as_slice());
    let mut decoded = String::new();
    inflater.read_to_string(&mut decoded)?;
    assert_eq!(decoded, "a valid gzip payload");
    Ok(())
}

#[test]
fn file_scans_share_the_stream_work_budget_and_keep_the_fast_profile_cap()
-> Result<(), Box<dyn Error>> {
    use crate::arguments::RecoveryProfile;
    let mut budget = StreamingBudget {
        work: 500,
        output: 10,
        zip: 10,
        attempts: 1,
    };
    assert_eq!(budget.range_work_limit(10, 20, RecoveryProfile::Fast), 20);
    assert_eq!(
        budget.range_work_limit(10, 20, RecoveryProfile::Normal),
        500
    );
    budget.charge_range_work(400)?;
    assert_eq!(
        budget.range_work_limit(10, 20, RecoveryProfile::Normal),
        100
    );
    assert!(budget.charge_range_work(101).is_err());
    budget.charge_range_work(100)?;
    assert_eq!(budget.range_work_limit(10, 20, RecoveryProfile::Normal), 0);
    Ok(())
}

#[test]
fn source_observation_charges_both_alphabet_scans_and_bounded_proposals()
-> Result<(), Box<dyn Error>> {
    let proposal = transform_proposal_scan_work_bound(4).ok_or("proposal work overflow")?;
    assert_eq!(
        observation_work(4).ok_or("observation work overflow")?,
        8 + proposal
    );
    Ok(())
}

#[test]
fn source_observation_is_skipped_when_its_work_cannot_be_admitted() -> Result<(), Box<dyn Error>> {
    let mut budget = StreamingBudget {
        work: 10,
        output: 100,
        zip: 100,
        attempts: 1,
    };
    assert!(budget.reserve_observation(100)?.is_none());
    assert_eq!(budget.work, 10);
    let required = observation_work(1).ok_or("observation work overflow")?;
    budget.work = required;
    assert_eq!(budget.reserve_observation(1)?, Some(required));
    assert_eq!(budget.work, 0);
    Ok(())
}

#[test]
fn source_identity_work_is_reserved_for_memory_and_file_inputs() -> Result<(), Box<dyn Error>> {
    use crate::{arguments::RecoveryOptions, refine::policy::RefinePolicy};
    use std::fs;

    let directory = tempfile::tempdir()?;
    for name in ["first.bin", "second.bin"] {
        fs::write(directory.path().join(name), b"0123456789")?;
    }
    fs::write(directory.path().join("small.bin"), b"x")?;
    fs::write(
        directory.path().join("manifest.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "artifacts": [
                {"file": "first.bin", "byte_length": 10},
                {"file": "second.bin", "byte_length": 10},
                {"file": "small.bin", "byte_length": 1}
            ]
        }))?,
    )?;
    let input = crate::refine::prepare_input_set(directory.path())?;
    let sources = crate::refine::read_sources(&input, 1, 1, &Job::new("source budget"))?;
    let mut policy = RefinePolicy::new(&RecoveryOptions::default(), false)?;
    policy.stream_work_limit = 22;
    assert!(StreamingBudget::new(&policy, &sources).is_err());
    policy.stream_work_limit = 23;
    let mut budget = StreamingBudget::new(&policy, &sources)?;
    assert_eq!(budget.work, 0);
    assert!(budget.reserve_observation(10)?.is_none());
    budget.begin_source()?;
    assert_eq!(budget.work, 1);
    Ok(())
}

#[test]
fn disabled_observation_preserves_the_input_without_collecting_syntax() -> Result<(), Box<dyn Error>>
{
    use super::super::ObservingReader;
    use std::io::Read;
    let source = b"abcdef123456";
    let mut reader = ObservingReader::new(source.as_slice(), false);
    let mut actual = Vec::new();
    reader.read_to_end(&mut actual)?;
    assert_eq!(actual.as_slice(), source.as_slice());
    assert!(reader.finish().is_none());
    Ok(())
}

#[test]
fn zip_expansion_from_earlier_sources_reduces_the_shared_budget() -> Result<(), Box<dyn Error>> {
    let mut budget = StreamingBudget {
        work: 100,
        output: 100,
        zip: 10,
        attempts: 2,
    };
    budget.charge_zip_work(7)?;
    assert_eq!(budget.zip, 3);
    assert!(budget.charge_zip_work(4).is_err());
    assert_eq!(budget.zip, 3);
    budget.charge_zip_work(3)?;
    assert_eq!(budget.zip, 0);
    Ok(())
}

#[test]
fn derived_ranges_share_the_spools_reserved_publication_work() -> Result<(), Box<dyn Error>> {
    use super::super::ranges::reserve_publication;
    let bytes = vec![b'a'; 32];
    let memory = MemoryBudget::new(1024 * 1024);
    let job = Job::new("derived range publication work");
    let mut budget = StreamingBudget {
        work: 5,
        output: 100,
        zip: 0,
        attempts: 1,
    };
    with_stream_source(&bytes, &job, &memory, &mut budget, |context| {
        let mut reserved = 10;
        assert!(reserve_publication(context, 12, &mut reserved)?);
        assert_eq!(reserved, 0);
        assert_eq!(context.budget.work, 3);
        assert_eq!(context.report.work_bytes, 2);
        assert!(!reserve_publication(context, 4, &mut reserved)?);
        assert_eq!(context.budget.work, 3);
        assert_eq!(context.report.omissions.len(), 1);
        Ok(())
    })?;
    Ok(())
}

#[test]
fn transform_workspace_pressure_remains_typed_and_reads_no_source_bytes()
-> Result<(), Box<dyn Error>> {
    use super::super::transform_source;
    use l2_workbench::{
        derivation::STREAM_WORKSPACE_BYTES,
        job::{Counter, MemoryClass, MemoryError},
    };
    let bytes = vec![b'a'; 8192];
    let job = Job::new("stream workspace pressure");
    let memory = MemoryBudget::new(STREAM_WORKSPACE_BYTES);
    let held = memory.try_reserve(MemoryClass::Cache, 1)?;
    let mut budget = StreamingBudget {
        work: 100_000,
        output: 100_000,
        zip: 100_000,
        attempts: 1,
    };
    with_stream_source(&bytes, &job, &memory, &mut budget, |context| {
        let error = transform_source(context, &Operation::HexDecode {})
            .err()
            .ok_or("workspace pressure became an omission")?;
        assert!(matches!(
            error.downcast_ref::<MemoryError>(),
            Some(MemoryError::Limit { .. })
        ));
        assert_eq!(context.report.omissions.len(), 0);
        Ok(())
    })?;
    assert_eq!(
        job.snapshot()?
            .counters
            .get(&Counter::SourceReadBytes)
            .copied()
            .unwrap_or(0),
        0
    );
    assert_eq!(memory.snapshot()?.used_bytes, held.bytes());
    Ok(())
}

#[test]
fn failed_transform_charges_work_and_source_reads_before_the_next_input()
-> Result<(), Box<dyn Error>> {
    use super::super::transform_source;
    use l2_workbench::job::Counter;
    let mut bytes = vec![b'a'; 8192];
    *bytes.first_mut().ok_or("empty test source")? = b'!';
    let mut planning = StreamingBudget {
        work: 1_000_000,
        output: bytes.len(),
        zip: 0,
        attempts: 1,
    };
    let reservation = planning
        .reserve(bytes.len(), &Operation::HexDecode {})
        .ok_or("test reservation missing")?;
    let mut budget = StreamingBudget {
        work: reservation.work,
        output: reservation.output,
        zip: 0,
        attempts: 2,
    };
    let memory = MemoryBudget::new(8 * 1024 * 1024);
    let job = Job::new("failed source transform");
    with_stream_source(&bytes, &job, &memory, &mut budget, |context| {
        assert!(transform_source(context, &Operation::HexDecode {})?.is_none());
        assert_eq!(context.budget.work, 0);
        assert_eq!(context.budget.output, 0);
        assert_eq!(context.report.work_bytes, reservation.work);
        assert_eq!(context.report.omissions.len(), 1);
        Ok(())
    })?;
    let next = vec![b'a'; bytes.len()];
    with_stream_source(&next, &job, &memory, &mut budget, |context| {
        assert!(transform_source(context, &Operation::HexDecode {})?.is_none());
        assert_eq!(context.report.omissions.len(), 1);
        Ok(())
    })?;
    assert_eq!(
        job.snapshot()?
            .counters
            .get(&Counter::SourceReadBytes)
            .copied()
            .unwrap_or(0),
        u64::try_from(bytes.len())?
    );
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn cancelled_transform_closes_its_private_spool_without_publishing() -> Result<(), Box<dyn Error>> {
    use super::super::transform_source;
    const CHILD: &str = "L2_STREAM_CANCEL_SPOOL_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe()?)
            .args([
                "refine::range_transform::budget::tests::cancelled_transform_closes_its_private_spool_without_publishing",
                "--exact",
            ])
            .env(CHILD, "1")
            .output()?;
        assert!(
            output.status.success(),
            "cancellation child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }
    let bytes = vec![b'a'; 8192];
    let memory = MemoryBudget::new(8 * 1024 * 1024);
    let job = Job::new("cancelled stream");
    let mut budget = StreamingBudget {
        work: 100_000,
        output: 100_000,
        zip: 0,
        attempts: 1,
    };
    with_stream_source(&bytes, &job, &memory, &mut budget, |context| {
        let open_before = std::fs::read_dir("/proc/self/fd")?.count();
        job.request_cancel();
        let error = transform_source(context, &Operation::HexDecode {})
            .err()
            .ok_or("cancelled stream completed")?;
        assert!(error.to_string().contains("cancel"), "{error}");
        assert_eq!(context.report.omissions.len(), 0);
        assert!(context.analysis.file_artifacts.is_empty());
        let open_after = std::fs::read_dir("/proc/self/fd")?.count();
        assert_eq!(open_before, open_after, "private spool remained open");
        Ok(())
    })?;
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

fn with_stream_source(
    bytes: &[u8],
    job: &Job,
    memory: &MemoryBudget,
    budget: &mut StreamingBudget,
    action: impl FnOnce(&mut super::super::StreamContext<'_>) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    use super::super::{ObservingReader, StreamContext};
    use crate::refine::analysis::AnalyzedSources;
    use l2_workbench::{
        artifact::{AnalysisStatus, ArtifactAnalysis, ArtifactAnalysisOptions},
        job::MemoryClass,
    };
    use std::{fs, io};

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.hex");
    fs::write(&path, bytes)?;
    let input = crate::refine::prepare_input_set(&path)?;
    let sources = crate::refine::read_sources(&input, 1, 1, job)?;
    let source = sources.first().ok_or("source missing")?;
    let mut report_memory = memory.try_reserve(MemoryClass::Executor, 0)?;
    let mut omission_memory = memory.try_reserve(MemoryClass::Executor, 0)?;
    let mut analysis = AnalyzedSources::new(4096, 0, memory)?;
    let mut report = ArtifactAnalysis {
        source_sha256: l2_workbench::sha256(bytes),
        source_length: bytes.len(),
        artifacts: Vec::new(),
        status: AnalysisStatus::Partial,
        omissions: Vec::new(),
        region_transform_reports: Vec::new(),
        work_bytes: 0,
        zip_expanded_work_bytes: 0,
    };
    let mut observed = ObservingReader::new(bytes, true);
    io::copy(&mut observed, &mut io::sink())?;
    let mut context = StreamContext {
        analysis: &mut analysis,
        input: &input,
        source_index: 0,
        source,
        observation: observed.finish().ok_or("observation missing")?,
        report: &mut report,
        options: ArtifactAnalysisOptions::default(),
        job,
        memory,
        report_memory: &mut report_memory,
        omission_memory: &mut omission_memory,
        budget,
        profile: crate::arguments::RecoveryProfile::Normal,
    };
    action(&mut context)
}
