use super::{
    Fixture, ResultDirectory, ResultKind, TestResult, json_field, json_field_mut, read_manifest,
    write_manifest,
};
use l2_workbench::job::{Counter, Job, MemoryBudget, cache::SourceIdentity};
use serde_json::Value;
use std::{fs, path::Path};

fn write_result(fixture: &Fixture, staging: &Path, artifact_digest: bool) -> TestResult {
    fixture.write_gzip_output(staging, "artifact.bin", b"artifact-content", b"summary")?;
    fs::write(staging.join("limitations.txt"), b"limitations")?;
    if artifact_digest {
        let SourceIdentity::Sha256(digest) =
            SourceIdentity::sha256_file(staging.join("artifact.bin"))?
        else {
            return Err("artifact digest is unavailable".into());
        };
        let mut manifest = read_manifest(staging)?;
        *json_field_mut(&mut manifest, "/artifacts/0")?
            .as_object_mut()
            .ok_or("artifact record is not an object")?
            .entry("sha256")
            .or_insert(Value::Null) = Value::String(digest);
        write_manifest(staging, &manifest)?;
    }
    Ok(())
}

fn publish_result(fixture: &Fixture, job: &Job, artifact_digest: bool) -> TestResult {
    ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?.publish(
        &fixture.identity,
        job,
        |staging| write_result(fixture, staging, artifact_digest),
    )?;
    Ok(())
}

#[test]
fn strict_reuse_accepts_unchanged_outputs_with_matching_digests() -> TestResult {
    let fixture = Fixture::new()?;
    publish_result(&fixture, &Job::new("publish"), true)?;
    let manifest = read_manifest(&fixture.output)?;
    let outputs = json_field(&manifest, "/l2solver_result/output_files")?
        .as_array()
        .ok_or("output stamps are missing")?;
    assert_eq!(outputs.len(), 4);
    for output in outputs {
        let name = output
            .get("file")
            .and_then(Value::as_str)
            .ok_or("output file name is missing")?;
        let actual = SourceIdentity::sha256_file(fixture.output.join(name))?;
        let SourceIdentity::Sha256(actual) = actual else {
            return Err("output digest is unavailable".into());
        };
        assert_eq!(
            output.get("sha256").and_then(Value::as_str),
            Some(actual.as_str())
        );
    }
    let existing = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    assert!(
        existing
            .reuse(
                &fixture.identity,
                Some(&fixture.input),
                true,
                &Job::new("reuse")
            )?
            .is_some_and(|result| result.complete)
    );
    Ok(())
}

#[test]
fn strict_reuse_rejects_same_length_changes_to_each_non_artifact_output() -> TestResult {
    for name in ["summary.txt", "evidence.jsonl.gz", "limitations.txt"] {
        let fixture = Fixture::new()?;
        publish_result(&fixture, &Job::new("publish"), false)?;
        let path = fixture.output.join(name);
        let mut bytes = fs::read(&path)?;
        let first = bytes.first_mut().ok_or("test output must not be empty")?;
        *first ^= 1;
        fs::write(path, bytes)?;

        let existing = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
        assert!(
            existing
                .reuse(
                    &fixture.identity,
                    Some(&fixture.input),
                    true,
                    &Job::new("reuse")
                )
                .is_err(),
            "strict reuse accepted a same-length change to {name}"
        );
        assert!(
            existing
                .reuse(
                    &fixture.identity,
                    Some(&fixture.input),
                    false,
                    &Job::new("reuse")
                )
                .is_err(),
            "fast reuse missed a metadata change to {name}"
        );
    }
    Ok(())
}

#[test]
fn legacy_unhashed_output_requires_refresh_for_strict_reuse() -> TestResult {
    let fixture = Fixture::new()?;
    publish_result(&fixture, &Job::new("publish"), false)?;
    let mut manifest = read_manifest(&fixture.output)?;
    let outputs = json_field_mut(&mut manifest, "/l2solver_result/output_files")?
        .as_array_mut()
        .ok_or("output stamps are missing")?;
    let summary = outputs
        .iter_mut()
        .find(|output| output.get("file").and_then(Value::as_str) == Some("summary.txt"))
        .ok_or("summary stamp is missing")?;
    *summary
        .get_mut("sha256")
        .ok_or("summary digest is missing")? = Value::Null;
    write_manifest(&fixture.output, &manifest)?;

    let existing = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    assert!(
        existing
            .reuse(
                &fixture.identity,
                Some(&fixture.input),
                false,
                &Job::new("reuse")
            )?
            .is_some()
    );
    let Err(error) = existing.reuse(
        &fixture.identity,
        Some(&fixture.input),
        true,
        &Job::new("reuse"),
    ) else {
        return Err("strict reuse accepted an unhashed output".into());
    };
    assert!(error.to_string().contains("--refresh"), "{error}");
    Ok(())
}

#[test]
fn publication_digest_work_is_counted_without_rehashing_manifest_artifacts() -> TestResult {
    let fixture = Fixture::new()?;
    let job = Job::new("publish");
    publish_result(&fixture, &job, true)?;
    let mut expected = 0_u64;
    for name in ["summary.txt", "evidence.jsonl.gz", "limitations.txt"] {
        expected += fs::metadata(fixture.output.join(name))?.len();
    }
    assert_eq!(
        job.snapshot()?.counters.get(&Counter::Bytes),
        Some(&expected)
    );
    Ok(())
}

#[test]
fn publication_digest_buffer_obeys_the_job_memory_budget() -> TestResult {
    let fixture = Fixture::new()?;
    let memory = MemoryBudget::new(0);
    let job = Job::with_memory_budget("publish", &memory);
    let Err(error) = publish_result(&fixture, &job, false) else {
        return Err("publication ignored its digest buffer budget".into());
    };
    assert!(
        crate::memory_error::find(error.as_ref()).is_some(),
        "{error}"
    );
    assert!(!fixture.output.exists());
    Ok(())
}

#[test]
fn strict_reuse_accounts_for_output_reads_and_admits_the_hash_buffer() -> TestResult {
    let fixture = Fixture::new()?;
    publish_result(&fixture, &Job::new("publish"), false)?;
    let existing = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let memory = MemoryBudget::new(1024 * 1024);
    let job = Job::with_memory_budget("strict reuse", &memory);
    assert!(
        existing
            .reuse(&fixture.identity, Some(&fixture.input), true, &job)?
            .is_some()
    );
    let mut expected = 0_u64;
    for name in [
        "artifact.bin",
        "summary.txt",
        "evidence.jsonl.gz",
        "limitations.txt",
    ] {
        expected += fs::metadata(fixture.output.join(name))?.len();
    }
    assert_eq!(
        job.snapshot()?.counters.get(&Counter::Bytes),
        Some(&expected)
    );

    let denied_memory = MemoryBudget::new(0);
    let denied_job = Job::with_memory_budget("reuse without scratch", &denied_memory);
    assert!(
        existing
            .reuse(&fixture.identity, Some(&fixture.input), false, &denied_job)?
            .is_some(),
        "fast reuse does not need a hashing buffer"
    );
    let Err(error) = existing.reuse(&fixture.identity, Some(&fixture.input), true, &denied_job)
    else {
        return Err("strict reuse ignored its digest buffer budget".into());
    };
    assert!(
        crate::memory_error::find(error.as_ref()).is_some(),
        "{error}"
    );
    Ok(())
}

#[test]
fn cancelled_job_stops_strict_result_reuse() -> TestResult {
    let fixture = Fixture::new()?;
    publish_result(&fixture, &Job::new("publish"), false)?;
    let existing = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let job = Job::new("cancelled reuse");
    job.request_cancel();
    assert!(
        existing
            .reuse(&fixture.identity, Some(&fixture.input), true, &job)
            .is_err()
    );
    Ok(())
}

#[test]
fn named_output_recheck_rejects_replacement_of_the_held_file() -> TestResult {
    let fixture = Fixture::new()?;
    publish_result(&fixture, &Job::new("publish"), false)?;
    let existing = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let super::super::manifest::DirectoryState::Owned { prepared, .. } = &existing.state else {
        return Err("published result should be owned".into());
    };
    let held = prepared.open_file("summary.txt")?;
    super::super::stamp::verify_named_file(prepared, "summary.txt", &held.metadata()?)?;

    // Keep the original inode linked while the output name points to a different file
    let parent = fixture.output.parent().ok_or("fixture parent is missing")?;
    fs::rename(
        fixture.output.join("summary.txt"),
        parent.join("original-summary"),
    )?;
    fs::write(fixture.output.join("summary.txt"), b"SUMMARY")?;
    assert!(
        super::super::stamp::verify_named_file(prepared, "summary.txt", &held.metadata()?).is_err()
    );
    Ok(())
}
