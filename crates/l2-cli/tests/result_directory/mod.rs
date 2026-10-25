use l2_workbench::job::{Job, Phase, PhaseState, cache::SourceIdentity};
use serde_json::json;
use std::{error::Error, fs, io, path::PathBuf};
use tempfile::TempDir;

use crate::result_directory::{ResultDirectory, ResultIdentity, ResultKind};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct Fixture {
    _root: TempDir,
    input: PathBuf,
    output: PathBuf,
    identity: ResultIdentity,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let root = tempfile::tempdir()?;
        let input = root.path().join("capture.pcap");
        fs::write(&input, b"capture-input")?;
        let source = SourceIdentity::sha256_file(&input)?;
        let identity = ResultIdentity {
            kind: ResultKind::Extract,
            algorithm_version: 1,
            source,
            settings: json!({"flows": true, "limit": 7}),
        };

        Ok(Self {
            output: root.path().join("capture.export"),
            input,
            identity,
            _root: root,
        })
    }

    fn publish(&self, export_status: &str, artifact_bytes: &[u8]) -> TestResult {
        let destination = ResultDirectory::inspect(&self.output, ResultKind::Extract)?;
        let job = Job::new("extract");
        destination.publish(&self.identity, &job, |staging| {
            self.write_output(staging, export_status, artifact_bytes)
        })?;
        let snapshot = job.snapshot()?;
        assert_eq!(
            snapshot.phase(Phase::Publication).map(|phase| phase.state),
            Some(PhaseState::Completed)
        );
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(self.output.join("manifest.json"))?)?;
        assert_eq!(
            manifest["l2solver_result"]["job"]["current_phase"],
            "publication"
        );
        assert!(
            manifest["l2solver_result"]["job"]["phases"]
                .as_array()
                .is_some_and(|phases| phases.iter().any(|phase| {
                    phase["phase"] == "publication" && phase["state"] == "in_progress"
                }))
        );
        Ok(())
    }

    fn write_output(
        &self,
        staging: &std::path::Path,
        export_status: &str,
        artifact_bytes: &[u8],
    ) -> TestResult {
        fs::write(staging.join("artifact.bin"), artifact_bytes)?;
        fs::write(staging.join("summary.txt"), b"summary")?;
        fs::write(staging.join("evidence.jsonl"), b"")?;
        let source_sha256 = match &self.identity.source {
            SourceIdentity::Sha256(digest) => digest,
            SourceIdentity::Fast(_) => {
                return Err(io::Error::other("fixture needs SHA-256").into());
            }
            _ => return Err(io::Error::other("unsupported fixture identity").into()),
        };
        let manifest = json!({
            "schema_version": 1,
            "export_status": export_status,
            "full_source_coverage": {
                "source": {"source_id": format!("sha256:{source_sha256}")}
            },
            "artifacts": [{"file": "artifact.bin", "byte_length": artifact_bytes.len(), "provenance": []}]
        });
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec(&manifest)?,
        )?;
        Ok(())
    }
}

#[test]
fn newly_published_complete_result_is_reused_with_declared_artifacts() -> TestResult {
    let fixture = Fixture::new()?;
    let new_result = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    assert!(
        new_result
            .reuse(&fixture.identity, Some(&fixture.input), false)?
            .is_none()
    );

    fixture.publish("complete", b"artifact-content")?;

    let existing = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let reused = existing
        .reuse(&fixture.identity, Some(&fixture.input), false)?
        .ok_or("an owned result should be available")?;
    assert!(reused.complete);
    assert_eq!(reused.artifacts.len(), 1);
    assert_eq!(reused.artifacts[0].file, "artifact.bin");
    Ok(())
}

#[test]
fn partial_result_is_reused_as_partial_not_a_complete_negative() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("partial", b"partial-artifact")?;

    let existing = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let reused = existing
        .reuse(&fixture.identity, Some(&fixture.input), false)?
        .ok_or("an owned partial result should be reported")?;
    assert!(!reused.complete);
    Ok(())
}

#[test]
fn changed_policy_returns_actionable_conflict() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    let mut changed = fixture.identity.clone();
    changed.settings = json!({"flows": false, "limit": 7});

    let existing = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let error = existing
        .reuse(&changed, Some(&fixture.input), false)
        .expect_err("different policy must not reuse an old result");
    let message = error.to_string();
    assert!(message.contains("--refresh") || message.contains("-o"));
    Ok(())
}

#[test]
fn unrelated_existing_directory_is_rejected_during_inspection() -> TestResult {
    let fixture = Fixture::new()?;
    fs::create_dir(&fixture.output)?;
    fs::write(fixture.output.join("user-data.txt"), b"keep")?;

    let error = match ResultDirectory::inspect(&fixture.output, ResultKind::Extract) {
        Ok(_) => return Err("unowned output must be rejected before input processing".into()),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(message.contains("output directory"), "{message}");
    assert!(message.contains("choose an unused -o"), "{message}");
    assert!(!message.contains("--refresh"), "{message}");
    assert_eq!(fs::read(fixture.output.join("user-data.txt"))?, b"keep");
    Ok(())
}

#[test]
fn mutated_artifact_is_not_reused() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"original-artifact")?;
    fs::write(fixture.output.join("artifact.bin"), b"modified-artifact")?;

    let existing = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    assert!(
        existing
            .reuse(&fixture.identity, Some(&fixture.input), false)
            .is_err()
    );
    Ok(())
}

#[test]
fn extra_entry_invalidates_an_owned_result() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    fs::write(fixture.output.join("unexpected.txt"), b"not-owned")?;

    assert!(ResultDirectory::inspect(&fixture.output, ResultKind::Extract).is_err());
    Ok(())
}

#[test]
fn strict_reuse_detects_same_length_changed_input() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    fs::write(&fixture.input, b"changed-input")?;

    let existing = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    assert!(
        existing
            .reuse(&fixture.identity, Some(&fixture.input), true)
            .is_err()
    );
    Ok(())
}

#[test]
fn failed_refresh_keeps_the_previous_result_intact() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"original-artifact")?;
    let manifest_before = fs::read(fixture.output.join("manifest.json"))?;

    let destination = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let result = destination.publish(&fixture.identity, &Job::new("refresh"), |staging| {
        fs::write(staging.join("partial.txt"), b"unfinished")?;
        Err::<(), _>(io::Error::other("writer failed").into())
    });
    assert!(result.is_err());
    assert_eq!(
        fs::read(fixture.output.join("manifest.json"))?,
        manifest_before
    );
    assert_eq!(
        fs::read(fixture.output.join("artifact.bin"))?,
        b"original-artifact"
    );
    Ok(())
}

#[test]
fn cancellation_after_staging_keeps_the_previous_result_intact() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"original-artifact")?;
    let manifest_before = fs::read(fixture.output.join("manifest.json"))?;
    let destination = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let job = Job::new("cancelled refresh");
    let writer_job = job.clone();

    let result = destination.publish(&fixture.identity, &job, |staging| {
        let artifact = b"replacement-artifact";
        fs::write(staging.join("artifact.bin"), artifact)?;
        fs::write(staging.join("summary.txt"), b"new summary")?;
        fs::write(staging.join("evidence.jsonl"), b"")?;
        let source_sha256 = match &fixture.identity.source {
            SourceIdentity::Sha256(digest) => digest,
            SourceIdentity::Fast(_) => return Err(io::Error::other("fixture needs SHA-256").into()),
            _ => return Err(io::Error::other("unsupported fixture identity").into()),
        };
        let manifest = json!({
            "schema_version": 1,
            "export_status": "complete",
            "full_source_coverage": {
                "source": {"source_id": format!("sha256:{source_sha256}")}
            },
            "artifacts": [{"file": "artifact.bin", "byte_length": artifact.len(), "provenance": []}]
        });
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec(&manifest)?,
        )?;
        writer_job.request_cancel();
        Ok(())
    });

    assert!(result.is_err());
    assert_eq!(
        fs::read(fixture.output.join("manifest.json"))?,
        manifest_before
    );
    assert_eq!(
        fs::read(fixture.output.join("artifact.bin"))?,
        b"original-artifact"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn preexchange_failure_keeps_the_previous_result_intact() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"original-artifact")?;
    let manifest_before = fs::read(fixture.output.join("manifest.json"))?;
    let destination = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    crate::publish::test_hooks::set_before_directory_exchange(|| {
        Err(io::Error::other("injected pre-exchange failure"))
    });

    let result = destination.publish(&fixture.identity, &Job::new("failed refresh"), |staging| {
        fixture.write_output(staging, "complete", b"replacement-artifact")
    });

    assert!(result.is_err());
    assert_eq!(
        fs::read(fixture.output.join("manifest.json"))?,
        manifest_before
    );
    assert_eq!(
        fs::read(fixture.output.join("artifact.bin"))?,
        b"original-artifact"
    );
    Ok(())
}

#[test]
fn legacy_extract_requires_explicit_refresh() -> TestResult {
    let fixture = Fixture::new()?;
    fs::create_dir(&fixture.output)?;
    fs::write(fixture.output.join("artifact.bin"), b"legacy")?;
    let digest = match &fixture.identity.source {
        SourceIdentity::Sha256(digest) => digest,
        SourceIdentity::Fast(_) => return Err(io::Error::other("fixture needs SHA-256").into()),
        _ => return Err(io::Error::other("unsupported fixture identity").into()),
    };
    fs::write(
        fixture.output.join("manifest.json"),
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "export_status": "complete",
            "full_source_coverage": {"source": {"source_id": format!("sha256:{digest}")}},
            "artifacts": [{"file": "artifact.bin", "byte_length": 6, "provenance": []}]
        }))?,
    )?;
    fs::write(fixture.output.join("summary.txt"), b"legacy summary")?;
    fs::write(fixture.output.join("evidence.jsonl"), b"")?;

    let existing = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let error = existing
        .reuse(&fixture.identity, Some(&fixture.input), false)
        .expect_err("legacy extraction must not be treated as a cache hit");
    assert!(error.to_string().contains("--refresh"));
    Ok(())
}

#[test]
fn refine_result_identity_uses_the_ordered_manifest_source_set() -> TestResult {
    let root = tempfile::tempdir()?;
    let output = root.path().join("refined");
    let source_bytes = b"one refine source";
    let source_sha256 = l2_workbench::sha256(source_bytes);
    let source_identity_sha256 = crate::refine::refine_source_identity_sha256([(
        u64::try_from(source_bytes.len())?,
        source_sha256.as_str(),
    )])?;
    let identity = ResultIdentity {
        kind: ResultKind::Refine,
        algorithm_version: 1,
        source: SourceIdentity::from_sha256(source_identity_sha256)?,
        settings: json!({"profile": "balanced"}),
    };
    let destination = ResultDirectory::inspect(&output, ResultKind::Refine)?;
    destination.publish(&identity, &Job::new("refine"), |staging| {
        fs::write(staging.join("summary.txt"), b"refined summary")?;
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec(&json!({
                "schema_version": 1,
                "complete": true,
                "sources": [{"byte_length": source_bytes.len(), "sha256": source_sha256}],
                "artifacts": []
            }))?,
        )?;
        Ok(())
    })?;

    let existing = ResultDirectory::inspect(&output, ResultKind::Refine)?;
    let reused = existing
        .reuse(&identity, None, true)?
        .ok_or("an owned refine result should be available")?;
    assert!(reused.complete);
    assert!(reused.artifacts.is_empty());
    Ok(())
}

#[test]
fn symlinked_artifact_is_rejected() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    let outside = fixture.output.with_extension("outside");
    fs::write(&outside, b"outside")?;
    fs::remove_file(fixture.output.join("artifact.bin"))?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, fixture.output.join("artifact.bin"))?;
    #[cfg(not(unix))]
    return Ok(());

    assert!(ResultDirectory::inspect(&fixture.output, ResultKind::Extract).is_err());
    Ok(())
}

#[test]
fn hard_linked_artifact_is_rejected() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    let outside_link = fixture.output.with_extension("linked");
    fs::hard_link(fixture.output.join("artifact.bin"), &outside_link)?;

    assert!(ResultDirectory::inspect(&fixture.output, ResultKind::Extract).is_err());
    Ok(())
}

#[test]
fn destination_replacement_after_inspection_is_detected() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    let existing = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let displaced = fixture.output.with_extension("displaced");
    fs::rename(&fixture.output, &displaced)?;
    fs::create_dir(&fixture.output)?;

    assert!(
        existing
            .reuse(&fixture.identity, Some(&fixture.input), false)
            .is_err()
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn missing_destination_through_symlinked_parent_is_rejected() -> TestResult {
    let root = tempfile::tempdir()?;
    let real_parent = root.path().join("real");
    fs::create_dir(&real_parent)?;
    let linked_parent = root.path().join("linked");
    std::os::unix::fs::symlink(&real_parent, &linked_parent)?;

    assert!(
        ResultDirectory::inspect(&linked_parent.join("new-output"), ResultKind::Extract).is_err()
    );
    assert_eq!(fs::read_dir(real_parent)?.count(), 0);
    Ok(())
}
