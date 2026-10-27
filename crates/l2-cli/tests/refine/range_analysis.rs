use super::{run, run_with_job, structural_png, structural_zip};
use crate::arguments::{RecoveryOptions, RecoveryProfile, RefineOptions};
use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

#[cfg(target_os = "linux")]
pub(super) fn process_read_bytes() -> Result<u64, Box<dyn Error>> {
    let io = fs::read_to_string("/proc/self/io")?;
    Ok(io
        .lines()
        .find_map(|line| line.strip_prefix("rchar: "))
        .ok_or("rchar missing")?
        .parse()?)
}

#[cfg(target_os = "linux")]
#[test]
fn range_source_admission_and_analysis_read_content_once() -> Result<(), Box<dyn Error>> {
    use crate::refine::input::{prepare_input_set, read_sources_with_test_budget as read_sources};
    use l2_workbench::{artifact::ArtifactAnalysisOptions, job::Job};
    use std::process::Command;

    const CHILD_MARKER: &str = "L2_TEST_SINGLE_RANGE_PASS_CHILD";
    const LENGTH: u64 = 70 * 1024 * 1024;
    if std::env::var_os(CHILD_MARKER).is_none() {
        let output = Command::new(std::env::current_exe()?)
            .args(["refine::tests::range_analysis::range_source_admission_and_analysis_read_content_once", "--exact"])
            .env(CHILD_MARKER, "1")
            .output()?;
        assert!(
            output.status.success(),
            "child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("large.bin");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&input)?;
    file.set_len(LENGTH)?;
    let set = prepare_input_set(&input)?;
    let job = Job::new("single range pass");
    let before = process_read_bytes()?;
    let sources = read_sources(&set, 1024, 1024, &job)?;
    let mut options = ArtifactAnalysisOptions::default();
    options.limits.max_input_bytes = 1024;
    options.limits.max_total_work_bytes = 1024;
    let report = sources.first().ok_or("source missing")?.analyze_ranges(
        &set,
        0,
        options,
        &job,
        &l2_workbench::job::MemoryBudget::new(u64::MAX),
    )?;
    let bytes_read = process_read_bytes()? - before;
    assert!(
        bytes_read < LENGTH + 1024 * 1024,
        "read {bytes_read} bytes for a {LENGTH}-byte source"
    );
    let identity = l2_workbench::job::cache::SourceIdentity::sha256_file(&input)?;
    assert_eq!(
        serde_json::to_value(identity)?
            .get("value")
            .and_then(serde_json::Value::as_str),
        Some(report.report.source_sha256.as_str())
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn changing_a_large_source_during_analysis_prevents_publication() -> Result<(), Box<dyn Error>> {
    use std::{
        process::Command,
        thread,
        time::{Duration, Instant},
    };

    const CHILD_MARKER: &str = "L2_TEST_CHANGING_RANGE_CHILD";
    if std::env::var_os(CHILD_MARKER).is_none() {
        let output = Command::new(std::env::current_exe()?)
            .args(["refine::tests::range_analysis::changing_a_large_source_during_analysis_prevents_publication", "--exact"])
            .env(CHILD_MARKER, "1")
            .output()?;
        assert!(
            output.status.success(),
            "child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("large.bin");
    let destination = directory.path().join("result");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&input)?;
    file.set_len(70 * 1024 * 1024)?;
    let before = process_read_bytes()?;
    let changed_path = input.clone();
    let writer = thread::spawn(move || -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let read = process_read_bytes().map_err(|error| error.to_string())?;
            if read.saturating_sub(before) > 1024 * 1024 {
                let mut file = OpenOptions::new()
                    .write(true)
                    .open(changed_path)
                    .map_err(|error| error.to_string())?;
                file.seek(SeekFrom::Start(69 * 1024 * 1024))
                    .map_err(|error| error.to_string())?;
                file.write_all(b"changed")
                    .map_err(|error| error.to_string())?;
                file.sync_all().map_err(|error| error.to_string())?;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(String::from("analysis did not start reading"));
            }
            thread::sleep(Duration::from_millis(1));
        }
    });
    let options = RefineOptions {
        input,
        output: Some(destination.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            profile: RecoveryProfile::Fast,
            memory_limit: 48 * 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    let result = run(&options, &mut Vec::new());
    writer
        .join()
        .map_err(|_| "writer thread panicked")?
        .map_err(std::io::Error::other)?;
    assert!(result.is_err(), "changed source was accepted");
    assert!(!destination.exists(), "changed source was published");
    Ok(())
}

#[test]
fn large_manifest_member_with_wrong_digest_is_never_published() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("input");
    let destination = directory.path().join("result");
    fs::create_dir(&input)?;
    fs::write(input.join("member.bin"), vec![7_u8; 512 * 1024])?;
    fs::write(
        input.join("manifest.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1, "artifacts": [{"file": "member.bin", "byte_length": 512 * 1024, "sha256": "0".repeat(64)}]
        }))?,
    )?;
    let options = RefineOptions {
        input,
        output: Some(destination.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };
    let error = run(&options, &mut Vec::new())
        .err()
        .ok_or("wrong digest was accepted")?;
    assert!(error.to_string().contains("hash does not match"), "{error}");
    assert!(!destination.exists(), "failed analysis published a result");
    Ok(())
}

#[test]
fn large_sparse_input_carves_validated_cross_window_ranges_without_a_source_blob()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("large.bin");
    let destination = directory.path().join("result");
    let png = structural_png()?;
    let zip = structural_zip()?;
    let png_offsets = [4 * 1024 * 1024 - 4, 12 * 1024 * 1024 + 5];
    let zip_offset = 8 * 1024 * 1024 - 3;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&input)?;
    file.set_len(70 * 1024 * 1024)?;
    for offset in png_offsets {
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&png)?;
    }
    file.seek(SeekFrom::Start(zip_offset))?;
    file.write_all(&zip)?;
    file.sync_all()?;
    let options = RefineOptions {
        input: input.clone(),
        output: Some(destination.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            profile: RecoveryProfile::Fast,
            memory_limit: 48 * 1024 * 1024,
            ..RecoveryOptions::default()
        },
    };

    assert!(
        !run(&options, &mut Vec::new())?,
        "range analysis must report incomplete full-source coverage"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    let source = manifest.pointer("/sources/0").ok_or("missing source")?;
    assert_eq!(
        source
            .get("byte_length")
            .and_then(serde_json::Value::as_u64),
        Some(70 * 1024 * 1024)
    );
    assert_eq!(
        source.get("status").and_then(serde_json::Value::as_str),
        Some("partial")
    );
    assert!(
        source
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|reason| reason.contains("ZIP end observation is subject to work"))
    );
    let original_identity = l2_workbench::job::cache::SourceIdentity::sha256_file(&input)?;
    let identity = serde_json::to_value(original_identity)?;
    assert_eq!(source.get("sha256"), identity.get("value"));
    assert_eq!(fs::metadata(&input)?.len(), 70 * 1024 * 1024);

    let expected = [
        (png.as_slice(), png_offsets.as_slice()),
        (zip.as_slice(), std::slice::from_ref(&zip_offset)),
    ];
    assert_carved_artifacts(&manifest, &destination, &expected)?;
    let mut original_png = vec![0; png.len()];
    file.seek(SeekFrom::Start(
        *png_offsets.first().ok_or("missing PNG offset")?,
    ))?;
    file.read_exact(&mut original_png)?;
    assert_eq!(original_png, png);
    assert_fast_reuse(&options)
}

fn assert_fast_reuse(options: &RefineOptions) -> Result<(), Box<dyn Error>> {
    let job = l2_workbench::job::Job::new("large warm reuse");
    let mut reused_output = Vec::new();
    assert!(!run_with_job(options, &mut reused_output, &job)?);
    assert!(String::from_utf8(reused_output)?.contains("Reused existing refined result"));
    assert_eq!(
        job.snapshot()?
            .counters
            .get(&l2_workbench::job::Counter::CacheHits),
        Some(&1)
    );
    Ok(())
}

fn assert_carved_artifacts(
    manifest: &serde_json::Value,
    destination: &Path,
    expected: &[(&[u8], &[u64])],
) -> Result<(), Box<dyn Error>> {
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing artifacts")?;
    for &(bytes, offsets) in expected {
        let artifact = artifacts
            .iter()
            .find(|artifact| {
                artifact.get("sha256").and_then(serde_json::Value::as_str)
                    == Some(l2_workbench::sha256(bytes).as_str())
            })
            .ok_or("missing carved artifact")?;
        let name = artifact
            .get("file")
            .and_then(serde_json::Value::as_str)
            .ok_or("missing artifact name")?;
        assert_eq!(fs::read(destination.join(name))?, bytes);
        let length = u64::try_from(bytes.len())?;
        for offset in offsets {
            assert!(
                artifact
                    .get("origins")
                    .and_then(serde_json::Value::as_array)
                    .ok_or("missing origins")?
                    .iter()
                    .any(|origin| origin
                        .pointer("/origin/kind")
                        .and_then(serde_json::Value::as_str)
                        == Some("source_range")
                        && origin
                            .pointer("/origin/range/offset")
                            .and_then(serde_json::Value::as_u64)
                            == Some(*offset)
                        && origin
                            .pointer("/origin/range/length")
                            .and_then(serde_json::Value::as_u64)
                            == Some(length))
            );
        }
    }
    assert!(artifacts.iter().all(|artifact| {
        artifact
            .get("byte_length")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|length| length < 16 * 1024 * 1024)
    }));
    Ok(())
}

#[test]
fn changing_a_range_source_before_reopening_rejects_analysis() -> Result<(), Box<dyn Error>> {
    use crate::refine::input::{prepare_input_set, read_sources_with_test_budget as read_sources};
    use l2_workbench::{artifact::ArtifactAnalysisOptions, job::Job};

    let directory = tempfile::tempdir()?;
    let input = directory.path().join("source.bin");
    fs::write(&input, vec![0_u8; 2048])?;
    let set = prepare_input_set(&input)?;
    let sources = read_sources(&set, 1024, 1024, &Job::new("source"))?;
    let source = sources.first().ok_or("source missing")?;
    let mut file = OpenOptions::new().write(true).open(&input)?;
    file.seek(SeekFrom::Start(20))?;
    file.write_all(b"changed")?;
    file.sync_all()?;
    assert!(
        source
            .analyze_ranges(
                &set,
                0,
                ArtifactAnalysisOptions::default(),
                &Job::new("analyze"),
                &l2_workbench::job::MemoryBudget::new(u64::MAX)
            )
            .is_err(),
        "changed source was analyzed"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn many_range_sources_fit_a_small_process_descriptor_limit() -> Result<(), Box<dyn Error>> {
    use crate::refine::input::{prepare_input_set, read_sources_with_test_budget as read_sources};
    use l2_workbench::job::Job;
    use std::process::Command;

    const CHILD_MARKER: &str = "L2_TEST_RANGE_FD_LIMIT_CHILD";
    if std::env::var_os(CHILD_MARKER).is_none() {
        let output = Command::new("prlimit")
            .args(["--nofile=64:64", "--"])
            .arg(std::env::current_exe()?)
            .args(["refine::tests::range_analysis::many_range_sources_fit_a_small_process_descriptor_limit", "--exact"])
            .env(CHILD_MARKER, "1")
            .output()?;
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    let mut artifacts = Vec::new();
    for index in 0..128 {
        let name = format!("source-{index}.bin");
        fs::write(directory.path().join(&name), b"large source")?;
        artifacts.push(serde_json::json!({"file": name, "byte_length": 12}));
    }
    fs::write(
        directory.path().join("manifest.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1, "artifacts": artifacts
        }))?,
    )?;
    let set = prepare_input_set(directory.path())?;
    let sources = read_sources(&set, 1024, 4, &Job::new("descriptor limit"))?;
    assert_eq!(sources.len(), 128);
    let job = Job::new("reopen sources");
    for (index, source) in sources.iter().enumerate() {
        source.analyze_ranges(
            &set,
            index,
            l2_workbench::artifact::ArtifactAnalysisOptions::default(),
            &job,
            &l2_workbench::job::MemoryBudget::new(u64::MAX),
        )?;
    }
    Ok(())
}

#[test]
fn streamed_range_reader_checks_job_cancellation_between_reads() -> Result<(), Box<dyn Error>> {
    use crate::refine::{input::CancellableReader, read_budget::SourceReadBudget};
    use l2_workbench::{
        artifact::{ArtifactAnalysisOptions, analyze_artifacts_from_reader},
        job::{Counter, Job},
    };
    use std::io;

    const LENGTH: u64 = 1024 * 1024 * 1024;

    struct CancelAfterRead<'a> {
        job: &'a Job,
        reads: usize,
    }
    impl Read for CancelAfterRead<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            buffer.fill(0);
            self.job.request_cancel();
            Ok(buffer.len())
        }
    }
    let job = Job::new("cancel range read");
    let budget = SourceReadBudget::new(LENGTH + 1);
    budget.reserve(LENGTH + 1)?;
    let inner = CancelAfterRead {
        job: &job,
        reads: 0,
    };
    let mut reader = CancellableReader::new(inner, &job);
    let mut options = ArtifactAnalysisOptions::default();
    options.limits.max_input_bytes = 512;
    let error = analyze_artifacts_from_reader(&mut reader, usize::try_from(LENGTH)?, options)
        .err()
        .ok_or("cancelled range scan completed")?;
    assert!(error.to_string().contains("cancellation"));
    assert_eq!(
        job.snapshot()?.counters.get(&Counter::SourceReadBytes),
        Some(&512)
    );
    Ok(())
}

#[test]
fn short_source_read_counts_only_bytes_actually_returned() -> Result<(), Box<dyn Error>> {
    use crate::refine::{input::CancellableReader, read_budget::SourceReadBudget};
    use l2_workbench::{
        artifact::{ArtifactAnalysisOptions, analyze_artifacts_from_reader},
        job::{Counter, Job},
    };

    let job = Job::new("short read");
    let budget = SourceReadBudget::new(4097);
    budget.reserve(4097)?;
    let mut reader = CancellableReader::new(std::io::Cursor::new(vec![1_u8; 17]), &job);
    assert!(
        analyze_artifacts_from_reader(&mut reader, 4096, ArtifactAnalysisOptions::default())
            .is_err()
    );
    assert_eq!(
        job.snapshot()?.counters.get(&Counter::SourceReadBytes),
        Some(&17)
    );
    Ok(())
}

#[test]
fn exhausted_shared_case_memory_fails_without_publishing_a_result() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let inputs = directory.path().join("inputs");
    let destination = directory.path().join("result");
    fs::create_dir(&inputs)?;
    let mut artifacts = Vec::new();
    for index in 0_u8..2 {
        let mut bytes = Vec::new();
        for value in [index * 2, index * 2 + 1] {
            let mut png = structural_png()?;
            let end = png.len().checked_sub(12).ok_or("missing PNG end")?;
            png.truncate(end);
            super::append_png_chunk(&mut png, *b"tEXt", &[value; 40])?;
            super::append_png_chunk(&mut png, *b"IEND", &[])?;
            bytes.extend_from_slice(&png);
        }
        bytes.resize(251, 0);
        let name = format!("source-{index}.bin");
        fs::write(inputs.join(&name), &bytes)?;
        artifacts.push(serde_json::json!({"file": name, "byte_length": bytes.len()}));
    }
    fs::write(inputs.join("small.bin"), vec![3_u8; 100])?;
    artifacts.push(serde_json::json!({"file": "small.bin", "byte_length": 100}));
    fs::write(
        inputs.join("manifest.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1, "artifacts": artifacts
        }))?,
    )?;
    let options = RefineOptions {
        input: inputs,
        output: Some(destination.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            memory_limit: 1000,
            ..RecoveryOptions::default()
        },
    };
    let error = run(&options, &mut Vec::new())
        .err()
        .ok_or("case memory pressure was ignored")?;
    assert!(matches!(
        error.downcast_ref::<l2_workbench::job::MemoryError>(),
        Some(l2_workbench::job::MemoryError::Limit { .. })
    ));
    assert!(!destination.exists(), "memory pressure published a result");
    Ok(())
}

#[test]
fn exhausted_case_marks_a_later_memory_source_partial() -> Result<(), Box<dyn Error>> {
    use crate::refine::{
        analysis::analyze_sources, input::prepare_input_set, policy::RefinePolicy,
    };
    use l2_workbench::{
        artifact::AnalysisOmission,
        job::{Job, Phase},
    };

    let directory = tempfile::tempdir()?;
    let input = directory.path().join("input.bin");
    let png = structural_png()?;
    fs::write(&input, &png)?;
    let set = prepare_input_set(&input)?;
    let sources = [
        super::loaded_source("first", &png),
        super::loaded_source("second", b"later"),
    ];
    let recovery = RecoveryOptions::default();
    let mut policy = RefinePolicy::new(&recovery, false)?;
    policy.case_blob_limit = png.len();
    let job = Job::new("case limit");
    job.start(Phase::Expansion, None)?;
    job.start(Phase::TransformDiscovery, Some(2))?;
    let report = analyze_sources(
        &sources,
        &set,
        &policy,
        &recovery,
        None,
        &job,
        &l2_workbench::job::MemoryBudget::new(u64::MAX),
    )?;
    let later = report.source_records.get(1).ok_or("later source missing")?;
    assert!(later.omissions.iter().any(|omission| matches!(omission, AnalysisOmission::CaseBlobLimit { maximum } if *maximum == png.len())));
    assert!(!report.complete);
    Ok(())
}

#[test]
fn changing_manifest_membership_after_admission_is_rejected() -> Result<(), Box<dyn Error>> {
    use crate::refine::{
        ensure_input_unchanged,
        input::{fingerprint_sources, prepare_input_set},
        policy::RefinePolicy,
    };
    use l2_workbench::job::Job;

    let directory = tempfile::tempdir()?;
    fs::write(directory.path().join("first.bin"), b"same")?;
    fs::write(directory.path().join("second.bin"), b"same")?;
    let manifest = directory.path().join("manifest.json");
    let make_manifest = |name: &str| {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1, "artifacts": [{"file": name, "byte_length": 4}]
        }))
    };
    fs::write(&manifest, make_manifest("first.bin")?)?;
    let set = prepare_input_set(directory.path())?;
    let recovery = RecoveryOptions::default();
    let policy = RefinePolicy::new(&recovery, false)?;
    let job = Job::new("membership change");
    let sampled = fingerprint_sources(&set, policy.total_input_limit, policy.per_file_limit, &job)?;
    fs::write(&manifest, make_manifest("second.bin")?)?;
    assert!(
        ensure_input_unchanged(&set, &sampled, &policy, &job).is_err(),
        "changed manifest was accepted"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn replacing_the_input_directory_after_admission_is_rejected() -> Result<(), Box<dyn Error>> {
    use crate::refine::{
        ensure_input_unchanged,
        input::{fingerprint_sources, prepare_input_set},
        policy::RefinePolicy,
    };
    use l2_workbench::job::Job;

    let root = tempfile::tempdir()?;
    let input = root.path().join("input");
    fs::create_dir(&input)?;
    fs::write(input.join("one.bin"), b"same")?;
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1, "artifacts": [{"file": "one.bin", "byte_length": 4}]
    }))?;
    fs::write(input.join("manifest.json"), &manifest)?;
    let set = prepare_input_set(&input)?;
    let policy = RefinePolicy::new(&RecoveryOptions::default(), false)?;
    let job = Job::new("directory replacement");
    let sampled = fingerprint_sources(&set, policy.total_input_limit, policy.per_file_limit, &job)?;
    fs::rename(&input, root.path().join("moved"))?;
    fs::create_dir(&input)?;
    fs::write(input.join("one.bin"), b"same")?;
    fs::write(input.join("manifest.json"), &manifest)?;
    assert!(
        ensure_input_unchanged(&set, &sampled, &policy, &job).is_err(),
        "replaced directory was accepted"
    );
    Ok(())
}
