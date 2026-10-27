use super::{RefinePolicy, run, run_with_job};
use crate::{
    arguments::{RecoveryOptions, RefineOptions},
    refine::{input, output},
    result_directory::{ResultDirectory, ResultKind},
};
use l2_workbench::job::{Job, cache::SourceIdentity};
use std::{cell::Cell, error::Error, fs, io, path::Path};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn options(input: &Path, output: &Path) -> RefineOptions {
    RefineOptions {
        input: input.to_owned(),
        output: Some(output.to_owned()),
        dry_run: false,
        salvage: false,
        recovery: RecoveryOptions {
            no_cache: true,
            ..RecoveryOptions::default()
        },
    }
}

fn padded_png_source() -> TestResult<Vec<u8>> {
    let mut bytes = super::structural_png()?;
    bytes.resize(300_000, 0);
    Ok(bytes)
}

#[test]
fn warm_sample_match_reuses_without_calling_full_source_verification() -> TestResult {
    let directory = tempfile::tempdir()?;
    let input_path = directory.path().join("input.bin");
    let destination = directory.path().join("result");
    let source = padded_png_source()?;
    fs::write(&input_path, &source)?;
    let options = options(&input_path, &destination);
    run(&options, &mut Vec::new())?;

    let set = input::prepare_input_set(&input_path)?;
    let policy = RefinePolicy::new(&options.recovery, false)?;
    let sampled = input::fingerprint_sources(
        &set,
        policy.total_input_limit,
        policy.per_file_limit,
        &Job::new("sample"),
    )?;
    let identity =
        output::result_identity_with_source(sampled.identity.clone(), &options.recovery, &policy)?;
    let inspected = ResultDirectory::inspect(&destination, ResultKind::Refine)?;
    let called = Cell::new(false);
    let reused = inspected.reuse_refinement(&identity, &sampled.labels, false, || {
        called.set(true);
        Err(io::Error::other("unexpected full source verification").into())
    })?;

    assert!(
        reused.is_some(),
        "a matching sampled identity should reuse the result"
    );
    assert!(
        !called.get(),
        "a warm sample match must not read the whole source"
    );
    Ok(())
}

#[test]
fn strict_reuse_detects_unsampled_change_even_when_fast_hint_matches() -> TestResult {
    let directory = tempfile::tempdir()?;
    let input_path = directory.path().join("input.bin");
    let destination = directory.path().join("result");
    let mut source = padded_png_source()?;
    fs::write(&input_path, &source)?;
    let mut options = options(&input_path, &destination);
    run(&options, &mut Vec::new())?;

    // Model metadata or sample collisions by updating the hint to the changed file
    *source
        .get_mut(80_000)
        .ok_or("unsampled source byte is missing")? = 1;
    fs::write(&input_path, &source)?;
    let set = input::prepare_input_set(&input_path)?;
    let policy = RefinePolicy::new(&options.recovery, false)?;
    let sampled = input::fingerprint_sources(
        &set,
        policy.total_input_limit,
        policy.per_file_limit,
        &Job::new("sample"),
    )?;
    let manifest_path = destination.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    *manifest
        .pointer_mut("/l2solver_result/identity/source")
        .ok_or("result source identity is missing")? = serde_json::to_value(&sampled.identity)?;
    fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;

    assert!(
        run(&options, &mut Vec::new()).is_ok(),
        "normal reuse accepts its documented bounded hint"
    );
    options.recovery.strict_cache = true;
    let error = run_with_job(&options, &mut Vec::new(), &Job::new("strict"))
        .err()
        .ok_or("strict reuse accepted changed source bytes")?;
    assert!(error.to_string().contains("source bytes differ"), "{error}");
    Ok(())
}

#[test]
fn strong_legacy_receipt_falls_back_to_full_source_verification() -> TestResult {
    let directory = tempfile::tempdir()?;
    let input_path = directory.path().join("input.bin");
    let destination = directory.path().join("result");
    fs::write(&input_path, super::structural_png()?)?;
    let options = options(&input_path, &destination);
    run(&options, &mut Vec::new())?;
    let manifest_path = destination.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let strong = manifest
        .pointer("/l2solver_result/source_identity_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing digest")?;
    let identity = serde_json::to_value(SourceIdentity::from_sha256(strong.to_owned())?)?;
    *manifest
        .pointer_mut("/l2solver_result/identity/source")
        .ok_or("result source identity is missing")? = identity;
    fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;

    let mut output = Vec::new();
    assert!(run(&options, &mut output)?);
    assert!(String::from_utf8(output)?.contains("Reused existing refined result"));
    Ok(())
}

#[test]
fn changed_source_content_rejects_normal_reuse() -> TestResult {
    let directory = tempfile::tempdir()?;
    let input_path = directory.path().join("input.bin");
    let destination = directory.path().join("result");
    fs::write(&input_path, super::structural_png()?)?;
    let options = options(&input_path, &destination);
    run(&options, &mut Vec::new())?;
    fs::write(&input_path, b"different source")?;

    let error = run(&options, &mut Vec::new())
        .err()
        .ok_or("changed source was reused")?;
    assert!(error.to_string().contains("source bytes differ"), "{error}");
    Ok(())
}

#[test]
fn replaced_file_with_same_content_reuses_after_full_digest() -> TestResult {
    let directory = tempfile::tempdir()?;
    let input_path = directory.path().join("input.bin");
    let destination = directory.path().join("result");
    let bytes = super::structural_png()?;
    fs::write(&input_path, &bytes)?;
    let options = options(&input_path, &destination);
    run(&options, &mut Vec::new())?;
    let replacement = directory.path().join("replacement.bin");
    fs::write(&replacement, &bytes)?;
    fs::rename(&replacement, &input_path)?;

    let mut output = Vec::new();
    assert!(run(&options, &mut output)?);
    assert!(String::from_utf8(output)?.contains("Reused existing refined result"));
    Ok(())
}

#[test]
fn changed_manifest_digest_is_checked_before_reuse() -> TestResult {
    let directory = tempfile::tempdir()?;
    let input_dir = directory.path().join("input");
    let destination = directory.path().join("result");
    fs::create_dir(&input_dir)?;
    let bytes = super::structural_png()?;
    fs::write(input_dir.join("one.bin"), &bytes)?;
    let manifest_path = input_dir.join("manifest.json");
    let mut manifest = serde_json::json!({"schema_version": 1, "artifacts": [{
        "file": "one.bin", "byte_length": bytes.len(), "sha256": l2_workbench::sha256(&bytes)
    }]});
    fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    let options = options(&input_dir, &destination);
    run(&options, &mut Vec::new())?;
    *manifest
        .pointer_mut("/artifacts/0/sha256")
        .ok_or("artifact digest is missing")? = serde_json::json!("0".repeat(64));
    fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;

    let error = run(&options, &mut Vec::new())
        .err()
        .ok_or("changed manifest hash was reused")?;
    assert!(error.to_string().contains("hash does not match"), "{error}");
    Ok(())
}

#[test]
fn renamed_manifest_member_does_not_reuse_stale_source_label() -> TestResult {
    let directory = tempfile::tempdir()?;
    let input_dir = directory.path().join("input");
    let destination = directory.path().join("result");
    fs::create_dir(&input_dir)?;
    let bytes = super::structural_png()?;
    fs::write(input_dir.join("one.bin"), &bytes)?;
    let manifest_path = input_dir.join("manifest.json");
    let mut manifest = serde_json::json!({"schema_version": 1, "artifacts": [{
        "file": "one.bin", "byte_length": bytes.len()
    }]});
    fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    let options = options(&input_dir, &destination);
    run(&options, &mut Vec::new())?;
    fs::rename(input_dir.join("one.bin"), input_dir.join("two.bin"))?;
    *manifest
        .pointer_mut("/artifacts/0/file")
        .ok_or("artifact filename is missing")? = serde_json::json!("two.bin");
    fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;

    let error = run(&options, &mut Vec::new())
        .err()
        .ok_or("changed label was reused")?;
    assert!(
        error.to_string().contains("source labels differ"),
        "{error}"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn replaced_manifest_member_symlink_is_rejected_before_reuse() -> TestResult {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir()?;
    let input_dir = directory.path().join("input");
    let destination = directory.path().join("result");
    fs::create_dir(&input_dir)?;
    let bytes = super::structural_png()?;
    let original = input_dir.join("one.bin");
    fs::write(&original, &bytes)?;
    fs::write(
        input_dir.join("manifest.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1, "artifacts": [{"file": "one.bin", "byte_length": bytes.len()}]
        }))?,
    )?;
    let options = options(&input_dir, &destination);
    run(&options, &mut Vec::new())?;
    let moved = directory.path().join("moved.bin");
    fs::rename(&original, &moved)?;
    symlink(&moved, &original)?;

    assert!(
        run(&options, &mut Vec::new()).is_err(),
        "symlinked input was reused"
    );
    Ok(())
}

#[test]
fn fingerprint_admission_bounds_memory_and_accepts_range_backed_inputs() -> TestResult {
    let directory = tempfile::tempdir()?;
    let input_path = directory.path().join("input.bin");
    fs::write(&input_path, b"12345")?;
    let set = input::prepare_input_set(&input_path)?;
    let job = Job::new("input limits");
    assert!(input::fingerprint_sources(&set, 4, 10, &job).is_err());
    assert!(input::fingerprint_sources(&set, 10, 4, &job).is_ok());
    fs::remove_file(&input_path)?;
    assert!(input::fingerprint_sources(&set, 10, 10, &job).is_err());
    Ok(())
}
