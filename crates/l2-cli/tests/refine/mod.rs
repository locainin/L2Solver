use std::{
    error::Error,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use l2_cli::arguments::{RecoveryOptions, RecoveryProfile, RefineOptions};
use serde_json::json;

use super::policy::RefinePolicy;
use super::{
    LoadedSource, analyze_source_cached, analyzer_options, default_output_path, prepare_input_set,
    read_sources, result_identity, run_with_job,
};

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

    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].label, "object.bin");
    assert_eq!(sources[0].bytes, artifact);
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

    let input_set = prepare_input_set(directory.path())?;
    assert!(read_sources(&input_set, 1024, 1024, &l2_workbench::job::Job::new("test")).is_err());
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
    let mut recovery = RecoveryOptions::default();
    recovery.no_cache = true;
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
    let first_file = manifest["artifacts"][0]["file"]
        .as_str()
        .ok_or("manifest artifact name is missing")?;

    assert_eq!(fs::read(output_dir.join(first_file))?, png);
    assert!(output_dir.join("summary.txt").is_file());
    assert_eq!(
        manifest["artifacts"][0]["sha256"],
        l2_workbench::sha256(&png)
    );
    assert_eq!(
        manifest["artifacts"][0]["origins"][0]["origin"]["kind"],
        "source"
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
    let mut recovery = RecoveryOptions::default();
    recovery.no_cache = true;
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
    let artifact_file = manifest["artifacts"][0]["file"]
        .as_str()
        .ok_or("source artifact file name is missing")?;

    assert_eq!(fs::read(output_dir.join(artifact_file))?, bytes);
    assert_eq!(manifest["complete"], false);
    assert_eq!(manifest["sources"][0]["status"], "unsupported");
    Ok(())
}

#[test]
fn per_input_cache_reuses_the_complete_analysis_and_restores_artifact_bytes()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let cache = l2_workbench::job::cache::Cache::open_at(
        directory.path().join("cache"),
        directory.path().join("state"),
        16 * 1024 * 1024,
    )?;
    let bytes = structural_png()?;
    let source = LoadedSource {
        label: String::from("source.bin"),
        sha256: l2_workbench::sha256(&bytes),
        bytes: bytes.clone(),
    };
    let recovery = RecoveryOptions::default();
    let options = analyzer_options(&recovery, false, 4096, 8192);
    let job = l2_workbench::job::Job::new("cache test");
    let mut warnings = Vec::new();

    let first = analyze_source_cached(
        &source,
        options,
        &recovery,
        Some(&cache),
        &mut warnings,
        &job,
    )?;
    let second = analyze_source_cached(
        &source,
        options,
        &recovery,
        Some(&cache),
        &mut warnings,
        &job,
    )?;
    let snapshot = job.snapshot()?;

    assert_eq!(first, second);
    assert_eq!(second.artifacts[0].bytes, bytes);
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
    assert!(warnings.is_empty());
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
    let mut recovery = RecoveryOptions::default();
    recovery.no_cache = true;
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
fn strict_reuse_rejects_mutated_artifact_bytes() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("source.bin");
    let output_dir = directory.path().join("result.refined");
    let png = structural_png()?;
    fs::write(&input, &png)?;
    let mut recovery = RecoveryOptions::default();
    recovery.no_cache = true;
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
    let artifact_file = manifest["artifacts"][0]["file"]
        .as_str()
        .ok_or("manifest artifact name is missing")?;
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
    let mut recovery = RecoveryOptions::default();
    recovery.no_cache = true;
    recovery.quiet = true;
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
    let mut recovery = RecoveryOptions::default();
    recovery.no_cache = true;
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
    assert_eq!(
        manifest["sources"][0]["sha256"],
        l2_workbench::sha256(second_source)
    );
    assert_eq!(manifest["complete"], false);
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

fn loaded_source(label: &str, bytes: &[u8]) -> LoadedSource {
    LoadedSource {
        label: label.to_owned(),
        bytes: bytes.to_vec(),
        sha256: l2_workbench::sha256(bytes),
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
