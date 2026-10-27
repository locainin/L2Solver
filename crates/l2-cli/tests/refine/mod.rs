use std::{
    error::Error,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use l2_cli::arguments::{RecoveryOptions, RecoveryProfile, RefineOptions};
use serde_json::json;

use super::input::SourceData;
use super::policy::RefinePolicy;
use super::{
    LoadedSource, analyze_source_cached, analyzer_options, default_output_path, prepare_input_set,
    read_sources, result_identity, run_with_job,
};

mod early_reuse;
mod large_formats;
mod memory;
mod range_analysis;
mod read_budget;

fn run(options: &RefineOptions, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let job = l2_workbench::job::Job::new("refine test");
    run_with_job(options, output, &job)
}

#[test]
fn manifest_input_uses_only_listed_artifacts_and_ignores_sidecars() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let artifact = b"listed bytes";
    fs::write(directory.path().join("object.bin"), artifact)?;
    fs::write(directory.path().join("summary.txt"), b"not an artifact")?;
    fs::write(directory.path().join("stray.bin"), b"also not an artifact")?;
    fs::write(
        directory.path().join("manifest.json"),
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "artifacts": [{"file": "object.bin", "byte_length": artifact.len(), "nodes": []}]
        }))?,
    )?;

    let input_set = prepare_input_set(directory.path())?;
    let sources = read_sources(&input_set, 1024, 1024, &l2_workbench::job::Job::new("test"))?;
    let source = sources.first().ok_or("listed source is missing")?;

    assert_eq!(sources.len(), 1);
    assert_eq!(source.label, "object.bin");
    assert_eq!(source.bytes(), Some(artifact.as_slice()));
    Ok(())
}

#[test]
fn manifest_path_traversal_is_rejected_before_opening_files() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    fs::write(
        directory.path().join("manifest.json"),
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "artifacts": [{"file": "../outside.bin", "byte_length": 1}]
        }))?,
    )?;

    let error = prepare_input_set(directory.path())
        .err()
        .ok_or("traversal was accepted")?;
    assert!(error.to_string().contains("unsafe file name"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn standalone_symlink_input_is_rejected() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    let target = directory.path().join("target.bin");
    let link = directory.path().join("input.bin");
    fs::write(&target, b"source")?;
    symlink(&target, &link)?;

    assert!(prepare_input_set(&link).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn manifest_member_symlink_is_rejected() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    let target = directory.path().join("target.bin");
    fs::write(&target, b"source")?;
    symlink(&target, directory.path().join("listed.bin"))?;
    fs::write(
        directory.path().join("manifest.json"),
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "artifacts": [{"file": "listed.bin", "byte_length": 6}]
        }))?,
    )?;

    assert!(prepare_input_set(directory.path()).is_err());
    Ok(())
}

#[test]
fn dry_run_writes_no_files_and_reports_supported_png_work() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("source.bin");
    let output_dir = directory.path().join("result.refined");
    let png = structural_png()?;
    fs::write(&input, &png)?;
    let options = RefineOptions {
        input,
        output: Some(output_dir.clone()),
        dry_run: true,
        salvage: false,
        recovery: RecoveryOptions::default(),
    };
    let mut output = Vec::new();

    let complete = run(&options, &mut output)?;

    assert!(complete);
    assert!(!output_dir.exists());
    assert!(String::from_utf8(output)?.contains("Dry run: no files were written"));
    Ok(())
}

#[test]
fn result_directory_keeps_original_and_writes_manifest_and_summary() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("source.bin");
    let output_dir = directory.path().join("result.refined");
    let png = structural_png()?;
    fs::write(&input, &png)?;
    let recovery = RecoveryOptions {
        no_cache: true,
        ..RecoveryOptions::default()
    };
    let options = RefineOptions {
        input,
        output: Some(output_dir.clone()),
        dry_run: false,
        salvage: false,
        recovery,
    };
    let mut output = Vec::new();

    assert!(run(&options, &mut output)?);
    let manifest_bytes = fs::read(output_dir.join("manifest.json"))?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)?;
    let artifact = manifest_entry(&manifest, "artifacts", 0)?;
    let first_file = string_field(artifact, "file")?;

    assert_eq!(fs::read(output_dir.join(first_file))?, png);
    assert!(output_dir.join("summary.txt").is_file());
    assert_eq!(
        string_field(artifact, "sha256")?,
        l2_workbench::sha256(&png)
    );
    let origin_kind = artifact
        .get("origins")
        .and_then(serde_json::Value::as_array)
        .and_then(|origins| origins.first())
        .and_then(|origin| origin.get("origin"))
        .and_then(|origin| origin.get("kind"))
        .and_then(serde_json::Value::as_str)
        .ok_or("manifest artifact origin kind is missing")?;
    assert_eq!(origin_kind, "source");
    Ok(())
}

#[test]
fn refined_png_and_zip_reuse_analyzer_validation_for_names_and_export_provenance()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let artifacts = [
        ("image", structural_png()?, "png", "png_structure"),
        ("archive", structural_zip()?, "zip", "zip_structure"),
    ];

    for (label, bytes, extension, format) in artifacts {
        let input = directory.path().join(format!("{label}.bin"));
        let output_dir = directory.path().join(format!("{label}.refined"));
        fs::write(&input, &bytes)?;
        let options = RefineOptions {
            input,
            output: Some(output_dir.clone()),
            dry_run: false,
            salvage: false,
            recovery: RecoveryOptions {
                no_cache: true,
                ..RecoveryOptions::default()
            },
        };

        assert!(run(&options, &mut Vec::new())?);
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(output_dir.join("manifest.json"))?)?;
        assert_eq!(
            manifest
                .get("schema_version")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        let published = manifest
            .get("artifacts")
            .and_then(serde_json::Value::as_array)
            .and_then(|records| {
                records.iter().find(|record| {
                    record.get("sha256").and_then(serde_json::Value::as_str)
                        == Some(l2_workbench::sha256(&bytes).as_str())
                })
            })
            .ok_or("validated input was not selected for publication")?;
        let file = string_field(published, "file")?;
        assert!(
            file.ends_with(&format!(".{extension}")),
            "unexpected file name {file}"
        );
        let node = published
            .get("nodes")
            .and_then(serde_json::Value::as_array)
            .and_then(|nodes| nodes.first())
            .ok_or("export node provenance is missing")?;
        assert_eq!(
            node.get("structural_validation_status")
                .and_then(serde_json::Value::as_str),
            Some("validated")
        );
        assert_eq!(
            node.get("structural_validation_format")
                .and_then(serde_json::Value::as_str),
            Some(format)
        );
        assert_eq!(
            node.get("validated_as").and_then(serde_json::Value::as_str),
            Some(format)
        );

        let input_set = prepare_input_set(&output_dir)?;
        let reloaded = read_sources(
            &input_set,
            1024,
            1024,
            &l2_workbench::job::Job::new("refine output reinput test"),
        )?;
        assert!(
            reloaded
                .iter()
                .any(|source| source.bytes() == Some(bytes.as_slice()))
        );
    }
    Ok(())
}

#[test]
fn incomplete_region_search_has_a_reason_in_the_manifest_and_summary() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("partial.bin");
    let output_dir = directory.path().join("partial.refined");
    let bytes = b"x|".repeat(100);
    fs::write(&input, &bytes)?;
    let options = RefineOptions {
        input,
        output: Some(output_dir.clone()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            ..RecoveryOptions::default()
        },
    };

    assert!(!run(&options, &mut Vec::new())?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output_dir.join("manifest.json"))?)?;
    let source = manifest_entry(&manifest, "sources", 0)?;
    assert_eq!(string_field(source, "status")?, "partial");
    assert_eq!(
        source
            .get("omissions")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0),
        "the reason must cover incomplete region reports without top-level omissions"
    );
    let reason = string_field(source, "reason")?;
    assert!(
        reason.contains("region"),
        "unexpected partial reason: {reason}"
    );
    assert!(
        fs::read_to_string(output_dir.join("summary.txt"))?.contains(reason),
        "the summary must include the source limitation reason"
    );
    Ok(())
}

#[test]
fn unsupported_file_is_preserved_and_marked_incomplete() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("unknown.bin");
    let output_dir = directory.path().join("unknown.refined");
    let bytes = b"arbitrary bytes without supported structure";
    fs::write(&input, bytes)?;
    let recovery = RecoveryOptions {
        no_cache: true,
        ..RecoveryOptions::default()
    };
    let options = RefineOptions {
        input,
        output: Some(output_dir.clone()),
        dry_run: false,
        salvage: false,
        recovery,
    };
    let mut output = Vec::new();

    assert!(!run(&options, &mut output)?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output_dir.join("manifest.json"))?)?;
    let artifact = manifest_entry(&manifest, "artifacts", 0)?;
    let artifact_file = string_field(artifact, "file")?;

    assert_eq!(fs::read(output_dir.join(artifact_file))?, bytes);
    assert_eq!(
        manifest
            .get("complete")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    let source = manifest_entry(&manifest, "sources", 0)?;
    assert_eq!(string_field(source, "status")?, "unsupported");
    assert!(
        string_field(source, "reason")?.contains("no supported"),
        "unsupported inputs need a concise explanation"
    );
    Ok(())
}

#[test]
fn per_input_cache_ignores_version_9_and_reuses_version_10() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let cache = l2_workbench::job::cache::Cache::open_at(
        directory.path().join("cache"),
        directory.path().join("state"),
        16 * 1024 * 1024,
    )?;
    let bytes = structural_png()?;
    let source = LoadedSource {
        label: String::from("source.bin"),
        data: SourceData::Memory {
            bytes: bytes.clone(),
            sha256: l2_workbench::sha256(&bytes),
            _memory: None,
        },
    };
    let recovery = RecoveryOptions::default();
    let options = analyzer_options(&recovery, false, 4096, 8192);
    let job = l2_workbench::job::Job::new("cache test");
    let identity = l2_workbench::job::cache::SourceIdentity::from_sha256(
        source.digest().ok_or("missing digest")?.to_owned(),
    )?;
    let previous_policy = json!({
        "schema_version": 1,
        "transform_proposal_format_version":
            l2_workbench::recovery::proposals::TRANSFORM_PROPOSAL_FORMAT_VERSION,
        "analyzer": options,
        "profile": "normal",
    });
    let previous_key = l2_workbench::job::cache::StageKey::new(
        "file_artifact_analysis",
        1,
        "l2_artifact_analyzer_v9",
        &previous_policy,
        &identity,
        &[],
    )?;
    drop(
        cache
            .lease(&previous_key)?
            .commit(l2_workbench::job::cache::StageStatus::Complete, json!({}))?,
    );

    let first = analyze_source_cached(&source, options, &recovery, Some(&cache), &job)?;
    let second = analyze_source_cached(&source, options, &recovery, Some(&cache), &job)?;
    let snapshot = job.snapshot()?;

    assert_eq!(first, second);
    assert_eq!(
        second
            .artifacts
            .first()
            .ok_or("cached artifact bytes are missing")?
            .bytes,
        bytes
    );
    assert_eq!(
        snapshot
            .counters
            .get(&l2_workbench::job::Counter::CacheMisses),
        Some(&1)
    );
    assert_eq!(
        snapshot
            .counters
            .get(&l2_workbench::job::Counter::CacheHits),
        Some(&1)
    );
    assert!(snapshot.cache_fallbacks.records().is_empty());
    Ok(())
}

#[test]
fn per_input_cache_hit_does_not_repeat_analysis_progress_counters() -> Result<(), Box<dyn Error>> {
    use l2_workbench::job::{Counter, Phase};

    let directory = tempfile::tempdir()?;
    let cache = l2_workbench::job::cache::Cache::open_at(
        directory.path().join("cache"),
        directory.path().join("state"),
        16 * 1024 * 1024,
    )?;
    let archive = structural_zip()?;
    let bytes =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &archive).into_bytes();
    let source = loaded_source("source.bin", &bytes);
    let sources = [source];
    let input_path = directory.path().join("source.bin");
    fs::write(&input_path, &bytes)?;
    let input_set = prepare_input_set(&input_path)?;
    let recovery = RecoveryOptions::default();
    let policy = RefinePolicy::new(&recovery, false)?;

    let first_job = l2_workbench::job::Job::new("refine cold analysis");
    first_job.start(Phase::Expansion, None)?;
    first_job.start(Phase::TransformDiscovery, Some(1))?;
    let _first = super::analysis::analyze_sources(
        &sources,
        &input_set,
        &policy,
        &recovery,
        Some(&cache),
        &first_job,
        &l2_workbench::job::MemoryBudget::new(u64::MAX),
    )?;

    let second_job = l2_workbench::job::Job::new("refine cached analysis");
    second_job.start(Phase::Expansion, None)?;
    second_job.start(Phase::TransformDiscovery, Some(1))?;
    let _second = super::analysis::analyze_sources(
        &sources,
        &input_set,
        &policy,
        &recovery,
        Some(&cache),
        &second_job,
        &l2_workbench::job::MemoryBudget::new(u64::MAX),
    )?;
    let first = first_job.snapshot()?;
    let second = second_job.snapshot()?;

    for counter in [
        Counter::CandidatesExamined,
        Counter::Transforms,
        Counter::ExpandedMembers,
        Counter::ValidatedArtifacts,
    ] {
        assert_eq!(
            second.counters.get(&counter).copied().unwrap_or_default(),
            0,
            "cache hits do not repeat {counter:?} work"
        );
        assert!(
            first.counters.get(&counter).copied().unwrap_or_default() > 0,
            "cold analysis records {counter:?} work"
        );
    }
    assert_eq!(second.counters.get(&Counter::CacheHits), Some(&1));
    Ok(())
}

#[test]
fn default_destination_appends_refined_to_the_input_path() {
    let input = Path::new("capture.pcapng");
    assert_eq!(
        default_output_path(input),
        PathBuf::from("capture.pcapng.refined")
    );
}

#[test]
fn result_identity_uses_ordered_content_hashes_and_analysis_settings() -> Result<(), Box<dyn Error>>
{
    let first = b"first source";
    let second = b"second source";
    let sources = [
        loaded_source("private-first-label", first),
        loaded_source("private-second-label", second),
    ];
    let recovery = RecoveryOptions::default();
    let policy = RefinePolicy::new(&recovery, false)?;
    let identity = result_identity(&sources, &recovery, &policy)?;
    assert_eq!(identity.algorithm_version, 10);
    assert_eq!(
        identity.settings.get("analyzer_algorithm_version"),
        Some(&json!(10))
    );
    assert_eq!(
        identity.settings.get("analysis_receipt_schema_version"),
        Some(&json!(1))
    );
    assert_eq!(
        identity.settings.get("transform_proposal_format_version"),
        Some(&json!(
            l2_workbench::recovery::proposals::TRANSFORM_PROPOSAL_FORMAT_VERSION
        ))
    );
    let relabeled = [
        loaded_source("renamed-first", first),
        loaded_source("renamed-second", second),
    ];
    assert_eq!(identity, result_identity(&relabeled, &recovery, &policy)?);

    let reversed = [
        loaded_source("private-second-label", second),
        loaded_source("private-first-label", first),
    ];
    assert_ne!(
        identity.source,
        result_identity(&reversed, &recovery, &policy)?.source
    );
    let salvage_policy = RefinePolicy::new(&recovery, true)?;
    assert_ne!(
        identity.settings,
        result_identity(&sources, &recovery, &salvage_policy)?.settings
    );

    let mut fast_profile = recovery;
    fast_profile.profile = RecoveryProfile::Fast;
    let fast_policy = RefinePolicy::new(&fast_profile, false)?;
    assert_ne!(
        identity.settings,
        result_identity(&sources, &fast_profile, &fast_policy)?.settings
    );
    Ok(())
}

#[test]
fn matching_result_directory_is_reused_before_artifact_analysis() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("source.bin");
    let output_dir = directory.path().join("result.refined");
    let png = structural_png()?;
    fs::write(&input, &png)?;
    let recovery = RecoveryOptions {
        no_cache: true,
        ..RecoveryOptions::default()
    };
    let options = RefineOptions {
        input,
        output: Some(output_dir),
        dry_run: false,
        salvage: false,
        recovery,
    };
    let mut first_output = Vec::new();
    assert!(run(&options, &mut first_output)?);

    let job = l2_workbench::job::Job::new("refine reuse test");
    let mut second_output = Vec::new();
    assert!(run_with_job(&options, &mut second_output, &job)?);
    let snapshot = job.snapshot()?;

    assert!(String::from_utf8(second_output)?.contains("Reused existing refined result"));
    assert_eq!(
        snapshot
            .counters
            .get(&l2_workbench::job::Counter::CacheHits),
        Some(&1)
    );
    assert_eq!(
        snapshot
            .phase(l2_workbench::job::Phase::TransformDiscovery)
            .map(|phase| phase.state),
        Some(l2_workbench::job::PhaseState::Skipped)
    );
    Ok(())
}

#[test]
fn version_9_analyzer_result_is_not_reused() -> Result<(), Box<dyn Error>> {
    rejects_prior_result_version(StaleResultVersion::Analyzer)
}

#[test]
fn version_9_publication_result_is_not_reused() -> Result<(), Box<dyn Error>> {
    rejects_prior_result_version(StaleResultVersion::Publication)
}

#[derive(Clone, Copy)]
enum StaleResultVersion {
    Analyzer,
    Publication,
}

fn rejects_prior_result_version(version: StaleResultVersion) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("source.bin");
    let output_dir = directory.path().join("result.refined");
    fs::write(&input, structural_png()?)?;
    let recovery = RecoveryOptions {
        no_cache: true,
        ..RecoveryOptions::default()
    };
    let options = RefineOptions {
        input,
        output: Some(output_dir.clone()),
        dry_run: false,
        salvage: false,
        recovery,
    };
    let mut output = Vec::new();
    assert!(run(&options, &mut output)?);

    let manifest_path = output_dir.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let receipt = manifest
        .get_mut("l2solver_result")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("result receipt is missing")?;
    let identity = receipt
        .get_mut("identity")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("result identity is missing")?;
    match version {
        StaleResultVersion::Publication => {
            identity.insert("algorithm_version".to_owned(), json!(9));
        }
        StaleResultVersion::Analyzer => {
            let settings = identity
                .get_mut("settings")
                .and_then(serde_json::Value::as_object_mut)
                .ok_or("result settings are missing")?;
            settings.insert("analyzer_algorithm_version".to_owned(), json!(9));
        }
    }
    fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;

    let error = run(&options, &mut Vec::new())
        .err()
        .ok_or("version 9 result was reused under version 10")?;
    assert!(
        error
            .to_string()
            .contains("result policy or algorithm version differs")
    );
    Ok(())
}

#[test]
fn strict_reuse_rejects_mutated_artifact_bytes() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("source.bin");
    let output_dir = directory.path().join("result.refined");
    let png = structural_png()?;
    fs::write(&input, &png)?;
    let recovery = RecoveryOptions {
        no_cache: true,
        ..RecoveryOptions::default()
    };
    let mut options = RefineOptions {
        input,
        output: Some(output_dir.clone()),
        dry_run: false,
        salvage: false,
        recovery,
    };
    let mut first_output = Vec::new();
    assert!(run(&options, &mut first_output)?);

    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output_dir.join("manifest.json"))?)?;
    let artifact = manifest_entry(&manifest, "artifacts", 0)?;
    let artifact_file = string_field(artifact, "file")?;
    let artifact_path = output_dir.join(artifact_file);
    let mut mutated = fs::read(&artifact_path)?;
    let first_byte = mutated.first_mut().ok_or("artifact is empty")?;
    *first_byte ^= 0xff;
    fs::write(&artifact_path, &mutated)?;

    options.recovery.strict_cache = true;
    let error = run(&options, &mut Vec::new())
        .err()
        .ok_or("strict reuse accepted mutated artifact bytes")?;

    assert!(
        error
            .to_string()
            .contains("result output changed after publication")
    );
    assert_eq!(fs::read(artifact_path)?, mutated);
    Ok(())
}

#[test]
fn quiet_mode_suppresses_fresh_and_reused_completion_messages() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("source.bin");
    let output_dir = directory.path().join("result.refined");
    fs::write(&input, structural_png()?)?;
    let recovery = RecoveryOptions {
        no_cache: true,
        quiet: true,
        ..RecoveryOptions::default()
    };
    let options = RefineOptions {
        input,
        output: Some(output_dir),
        dry_run: false,
        salvage: false,
        recovery,
    };

    let mut fresh_output = Vec::new();
    assert!(run(&options, &mut fresh_output)?);
    let mut reused_output = Vec::new();
    assert!(run(&options, &mut reused_output)?);

    assert!(fresh_output.is_empty());
    assert!(reused_output.is_empty());
    Ok(())
}

#[test]
fn unrelated_result_path_is_rejected_before_input_admission() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let output_file = directory.path().join("occupied.refined");
    fs::write(&output_file, b"user file")?;
    let options = RefineOptions {
        input: directory.path().join("missing-input.bin"),
        output: Some(output_file),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions::default(),
    };
    let job = l2_workbench::job::Job::new("refine output preflight test");
    let mut output = Vec::new();

    let error = run_with_job(&options, &mut output, &job)
        .err()
        .ok_or("an unrelated output file was accepted")?;
    let snapshot = job.snapshot()?;

    assert!(error.to_string().contains("not a real directory"));
    assert_eq!(
        snapshot
            .phase(l2_workbench::job::Phase::Ingestion)
            .map(|phase| phase.state),
        Some(l2_workbench::job::PhaseState::Pending)
    );
    assert_eq!(
        fs::read(options.output.as_ref().ok_or("output missing")?)?,
        b"user file"
    );
    Ok(())
}

#[test]
fn refresh_replaces_only_the_owned_result_with_current_source_bytes() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("source.bin");
    let output_dir = directory.path().join("result.refined");
    let first_png = structural_png()?;
    let second_source = b"changed but unsupported source";
    fs::write(&input, &first_png)?;
    let recovery = RecoveryOptions {
        no_cache: true,
        ..RecoveryOptions::default()
    };
    let mut options = RefineOptions {
        input,
        output: Some(output_dir.clone()),
        dry_run: false,
        salvage: false,
        recovery,
    };
    let mut first_output = Vec::new();
    assert!(run(&options, &mut first_output)?);

    fs::write(&options.input, second_source)?;
    let mut rejected_output = Vec::new();
    assert!(run(&options, &mut rejected_output).is_err());
    options.recovery.refresh = true;
    let mut refreshed_output = Vec::new();

    assert!(!run(&options, &mut refreshed_output)?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output_dir.join("manifest.json"))?)?;
    let source = manifest_entry(&manifest, "sources", 0)?;
    assert_eq!(
        string_field(source, "sha256")?,
        l2_workbench::sha256(second_source)
    );
    assert_eq!(
        manifest
            .get("complete")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    Ok(())
}

fn structural_png() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = l2_workbench::artifact::PNG_SIGNATURE.to_vec();
    let mut header = [0_u8; 13];
    header[..4].copy_from_slice(&1_u32.to_be_bytes());
    header[4..8].copy_from_slice(&1_u32.to_be_bytes());
    header[8..].copy_from_slice(&[8, 2, 0, 0, 0]);
    append_png_chunk(&mut bytes, *b"IHDR", &header)?;
    append_png_chunk(&mut bytes, *b"IEND", &[])?;
    Ok(bytes)
}

fn structural_zip() -> Result<Vec<u8>, Box<dyn Error>> {
    use std::io::Cursor;

    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    archive.start_file(
        "member.bin",
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )?;
    archive.write_all(b"member payload")?;
    Ok(archive.finish()?.into_inner())
}

fn loaded_source(label: &str, bytes: &[u8]) -> LoadedSource {
    LoadedSource {
        label: label.to_owned(),
        data: SourceData::Memory {
            bytes: bytes.to_vec(),
            sha256: l2_workbench::sha256(bytes),
            _memory: None,
        },
    }
}

fn append_png_chunk(
    bytes: &mut Vec<u8>,
    kind: [u8; 4],
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    bytes.extend_from_slice(&u32::try_from(payload.len())?.to_be_bytes());
    bytes.extend_from_slice(&kind);
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&crc32fast::hash(&[kind.as_slice(), payload].concat()).to_be_bytes());
    Ok(())
}

fn manifest_entry<'a>(
    manifest: &'a serde_json::Value,
    array_name: &str,
    index: usize,
) -> Result<&'a serde_json::Value, Box<dyn Error>> {
    manifest
        .get(array_name)
        .and_then(serde_json::Value::as_array)
        .and_then(|entries| entries.get(index))
        .ok_or_else(|| format!("manifest {array_name} entry {index} is missing").into())
}

fn string_field<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str, Box<dyn Error>> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("manifest field {field} is missing or not a string").into())
}
