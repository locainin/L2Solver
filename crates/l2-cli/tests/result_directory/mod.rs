use l2_workbench::job::{Job, Phase, PhaseState, cache::SourceFingerprint, cache::SourceIdentity};
use serde_json::{Value, json};
use std::{error::Error, fs, io, path::PathBuf};
use tempfile::TempDir;

use crate::result_directory::{ResultDirectory, ResultIdentity, ResultKind};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

mod publication_transition;
mod publish;
mod snapshot;

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
            json_field(&manifest, "/l2solver_result/job/current_phase")?.as_str(),
            Some("publication")
        );
        let publication_started = json_field(&manifest, "/l2solver_result/job/phases")?
            .as_array()
            .is_some_and(|phases| {
                phases.iter().any(|phase| {
                    phase.get("phase").and_then(Value::as_str) == Some("publication")
                        && phase.get("state").and_then(Value::as_str) == Some("in_progress")
                })
            });
        assert!(publication_started);
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

    fn publish_with_gzip_evidence(&self) -> TestResult {
        let destination = ResultDirectory::inspect(&self.output, ResultKind::Extract)?;
        destination.publish(&self.identity, &Job::new("extract"), |staging| {
            self.write_gzip_output(staging, "artifact.bin", b"artifact-content", b"summary")
        })?;
        Ok(())
    }

    fn write_gzip_output(
        &self,
        staging: &std::path::Path,
        artifact_file: &str,
        artifact_bytes: &[u8],
        summary: &[u8],
    ) -> TestResult {
        let sidecar_file = "evidence.jsonl.gz";
        if artifact_file != sidecar_file {
            fs::write(staging.join(artifact_file), artifact_bytes)?;
        }
        fs::write(staging.join("summary.txt"), summary)?;
        fs::write(staging.join(sidecar_file), b"gzip-sidecar")?;
        let source_sha256 = match &self.identity.source {
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
            "evidence": {"file": sidecar_file},
            "artifacts": [{
                "file": artifact_file,
                "byte_length": artifact_bytes.len(),
                "provenance": []
            }]
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
    assert_eq!(
        reused
            .artifacts
            .first()
            .map(|artifact| artifact.file.as_str()),
        Some("artifact.bin")
    );
    Ok(())
}

#[test]
fn bounded_identity_deserialization_accepts_fast_source_fingerprints() -> TestResult {
    let fixture = Fixture::new()?;
    let identity = ResultIdentity {
        kind: ResultKind::Extract,
        algorithm_version: 1,
        source: SourceIdentity::Fast(SourceFingerprint::fast(&fixture.input)?),
        settings: json!({"profile": "balanced"}),
    };
    let serialized = serde_json::to_vec(&identity)?;
    let parsed: ResultIdentity = serde_json::from_slice(&serialized)?;
    assert_eq!(parsed, identity);

    let mut value = serde_json::to_value(&identity)?;
    *json_field_mut(&mut value, "/source/value/sample_sha256")? = json!("invalid");
    assert!(serde_json::from_value::<ResultIdentity>(value).is_err());
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
    let Err(error) = existing.reuse(&changed, Some(&fixture.input), false) else {
        return Err("different policy must not reuse an old result".into());
    };
    let message = error.to_string();
    assert!(message.contains("--refresh") || message.contains("-o"));
    Ok(())
}

#[test]
fn unrelated_existing_directory_is_rejected_during_inspection() -> TestResult {
    let fixture = Fixture::new()?;
    fs::create_dir(&fixture.output)?;
    fs::write(fixture.output.join("user-data.txt"), b"keep")?;

    let Err(error) = ResultDirectory::inspect(&fixture.output, ResultKind::Extract) else {
        return Err("unowned output must be rejected before input processing".into());
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
fn result_manifest_rejects_artifact_arrays_above_the_export_budget() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    let mut manifest = read_manifest(&fixture.output)?;
    set_json_field(
        &mut manifest,
        "/artifacts",
        json!(
            (0..=crate::result_directory::manifest::MAX_RESULT_ARTIFACTS)
                .map(|index| json!({
                    "file": format!("artifact-{index}.bin"),
                    "byte_length": 1,
                    "provenance": []
                }))
                .collect::<Vec<_>>()
        ),
    )?;
    write_manifest(&fixture.output, &manifest)?;

    assert_manifest_limit_error(&fixture.output, ResultKind::Extract)
}

#[test]
fn result_manifest_rejects_oversized_artifact_names_during_deserialization() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    let mut manifest = read_manifest(&fixture.output)?;
    *json_field_mut(&mut manifest, "/artifacts/0/file")? = json!("a".repeat(256));
    write_manifest(&fixture.output, &manifest)?;

    assert_manifest_limit_error(&fixture.output, ResultKind::Extract)
}

#[test]
fn result_manifest_rejects_malformed_json() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    fs::write(
        fixture.output.join("manifest.json"),
        b"{\"schema_version\":",
    )?;

    assert!(ResultDirectory::inspect(&fixture.output, ResultKind::Extract).is_err());
    Ok(())
}

#[test]
fn result_manifest_rejects_refine_source_arrays_above_the_input_budget() -> TestResult {
    let root = tempfile::tempdir()?;
    let output = root.path().join("refined");
    publish_refine_result(&output)?;
    let mut manifest = read_manifest(&output)?;
    set_json_field(
        &mut manifest,
        "/sources",
        json!(
            (0..=crate::result_directory::manifest::MAX_RESULT_SOURCES)
                .map(|_| json!({"byte_length": 1, "sha256": "a".repeat(64)}))
                .collect::<Vec<_>>()
        ),
    )?;
    write_manifest(&output, &manifest)?;

    assert_manifest_limit_error(&output, ResultKind::Refine)
}

#[test]
fn result_receipt_rejects_output_stamps_above_the_artifact_budget() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    let mut manifest = read_manifest(&fixture.output)?;
    let stamp = json!({
        "file": "artifact.bin",
        "byte_length": 16,
        "sha256": "a".repeat(64),
        "device_id": null,
        "file_id": null,
        "modified_seconds": null,
        "modified_nanoseconds": null,
        "changed_seconds": null,
        "changed_nanoseconds": null
    });
    set_json_field(
        &mut manifest,
        "/l2solver_result/output_files",
        json!(vec![
            stamp;
            crate::result_directory::manifest::MAX_RESULT_OUTPUT_STAMPS
                + 1
        ]),
    )?;
    write_manifest(&fixture.output, &manifest)?;

    assert_manifest_limit_error(&fixture.output, ResultKind::Extract)
}

#[test]
fn result_receipt_rejects_source_digest_arrays_above_the_input_budget() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    let mut manifest = read_manifest(&fixture.output)?;
    set_json_field(
        &mut manifest,
        "/l2solver_result/source_sha256s",
        json!(vec![
            "a".repeat(64);
            crate::result_directory::manifest::MAX_RESULT_SOURCES
                + 1
        ]),
    )?;
    write_manifest(&fixture.output, &manifest)?;

    assert_manifest_limit_error(&fixture.output, ResultKind::Extract)
}

#[test]
fn result_receipt_rejects_settings_arrays_over_the_node_budget() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    let mut manifest = read_manifest(&fixture.output)?;
    let values = vec![false; crate::result_directory::bounded::MAX_SETTINGS_ITEMS];
    set_json_field(
        &mut manifest,
        "/l2solver_result/identity/settings",
        json!(vec![values; 5]),
    )?;
    write_manifest(&fixture.output, &manifest)?;

    assert_manifest_limit_error(&fixture.output, ResultKind::Extract)
}

#[test]
fn result_receipt_rejects_settings_maps_over_the_entry_budget() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    let mut manifest = read_manifest(&fixture.output)?;
    set_json_field(
        &mut manifest,
        "/l2solver_result/identity/settings",
        json!(
            (0..=crate::result_directory::bounded::MAX_SETTINGS_ITEMS)
                .map(|index| (format!("setting-{index}"), json!(true)))
                .collect::<serde_json::Map<_, _>>()
        ),
    )?;
    write_manifest(&fixture.output, &manifest)?;

    assert_manifest_limit_error(&fixture.output, ResultKind::Extract)
}

#[test]
fn result_receipt_rejects_individually_oversized_settings_strings() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    let mut manifest = read_manifest(&fixture.output)?;
    insert_json_field(
        &mut manifest,
        "/l2solver_result/identity/settings",
        "large",
        json!("s".repeat(64 * 1024 + 1)),
    )?;
    write_manifest(&fixture.output, &manifest)?;

    assert_manifest_limit_error(&fixture.output, ResultKind::Extract)
}

#[test]
fn result_receipt_rejects_sixty_five_duplicate_phases() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    let mut manifest = read_manifest(&fixture.output)?;
    let phase = json_field(&manifest, "/l2solver_result/job/phases/0")?.clone();
    set_json_field(
        &mut manifest,
        "/l2solver_result/job/phases",
        json!(vec![phase; 65]),
    )?;
    write_manifest(&fixture.output, &manifest)?;

    assert_invalid_snapshot_error(&fixture.output)
}

#[test]
fn result_manifest_keeps_large_unrelated_report_fields_streamed() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    let mut manifest = read_manifest(&fixture.output)?;
    insert_json_field(
        &mut manifest,
        "",
        "large_report_field",
        json!("r".repeat(2 * 1024 * 1024)),
    )?;
    write_manifest(&fixture.output, &manifest)?;

    ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    Ok(())
}

#[test]
fn result_manifest_reader_enforces_the_limit_after_open() -> TestResult {
    let root = tempfile::tempdir()?;
    let path = root.path().join("manifest.json");
    fs::write(&path, br#"{"a":1}"#)?;

    let mut exact_limit = fs::File::open(&path)?;
    let parsed: serde_json::Value =
        crate::result_directory::manifest::deserialize_manifest_value(&mut exact_limit, 7)?;
    assert_eq!(json_field(&parsed, "/a")?.as_i64(), Some(1));

    let mut lower_limit = fs::File::open(&path)?;
    assert!(
        crate::result_directory::manifest::deserialize_manifest_value::<serde_json::Value>(
            &mut lower_limit,
            6
        )
        .is_err()
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn result_manifest_identity_detects_replacement_after_parse() -> TestResult {
    let root = tempfile::tempdir()?;
    let manifest = root.path().join("manifest.json");
    let replacement = root.path().join("replacement.json");
    fs::write(&manifest, b"original")?;
    let before = crate::result_directory::manifest::ManifestFileIdentity::from_metadata(
        &fs::File::open(&manifest)?.metadata()?,
    )?;

    fs::write(&replacement, b"replaced")?;
    fs::rename(&replacement, &manifest)?;
    let after = crate::result_directory::manifest::ManifestFileIdentity::from_metadata(
        &fs::File::open(&manifest)?.metadata()?,
    )?;

    assert!(
        crate::result_directory::manifest::ensure_same_manifest_identity(before, after).is_err()
    );
    Ok(())
}

fn read_manifest(directory: &std::path::Path) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_slice(&fs::read(
        directory.join("manifest.json"),
    )?)?)
}

fn write_manifest(directory: &std::path::Path, manifest: &serde_json::Value) -> TestResult {
    fs::write(
        directory.join("manifest.json"),
        serde_json::to_vec(manifest)?,
    )?;
    Ok(())
}

fn assert_manifest_limit_error(path: &std::path::Path, kind: ResultKind) -> TestResult {
    let Err(error) = ResultDirectory::inspect(path, kind) else {
        return Err("over-limit result manifest should be rejected during parsing".into());
    };
    let message = error.to_string();
    assert!(message.contains("limit"), "{message}");
    Ok(())
}

fn assert_invalid_snapshot_error(path: &std::path::Path) -> TestResult {
    let Err(error) = ResultDirectory::inspect(path, ResultKind::Extract) else {
        return Err("invalid job phase topology should be rejected".into());
    };
    let message = error.to_string();
    assert!(message.contains("phase"), "{message}");
    Ok(())
}

fn publish_refine_result(output: &std::path::Path) -> TestResult<ResultIdentity> {
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
    let destination = ResultDirectory::inspect(output, ResultKind::Refine)?;
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
    Ok(identity)
}

fn json_field<'a>(value: &'a Value, pointer: &str) -> TestResult<&'a Value> {
    value
        .pointer(pointer)
        .ok_or_else(|| io::Error::other(format!("missing JSON field at {pointer}")))
        .map_err(Into::into)
}

fn json_field_mut<'a>(value: &'a mut Value, pointer: &str) -> TestResult<&'a mut Value> {
    value
        .pointer_mut(pointer)
        .ok_or_else(|| io::Error::other(format!("missing JSON field at {pointer}")))
        .map_err(Into::into)
}

fn set_json_field(value: &mut Value, pointer: &str, replacement: Value) -> TestResult {
    *json_field_mut(value, pointer)? = replacement;
    Ok(())
}

fn insert_json_field(
    value: &mut Value,
    object_pointer: &str,
    key: &str,
    replacement: Value,
) -> TestResult {
    let object = if object_pointer.is_empty() {
        value.as_object_mut()
    } else {
        value
            .pointer_mut(object_pointer)
            .and_then(Value::as_object_mut)
    }
    .ok_or_else(|| io::Error::other(format!("missing JSON object at {object_pointer}")))?;
    let _previous_value = object.insert(key.to_owned(), replacement);
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
    let Err(error) = existing.reuse(&fixture.identity, Some(&fixture.input), false) else {
        return Err("legacy extraction must not be treated as a cache hit".into());
    };
    assert!(error.to_string().contains("--refresh"));
    Ok(())
}

#[test]
fn gzip_evidence_sidecar_is_owned_and_reused_from_its_manifest_name() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish_with_gzip_evidence()?;

    let existing = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let reused = existing
        .reuse(&fixture.identity, Some(&fixture.input), true)?
        .ok_or("a result with its declared gzip sidecar should be reusable")?;

    assert!(reused.complete);
    assert_eq!(reused.artifacts.len(), 1);
    assert_eq!(
        reused
            .artifacts
            .first()
            .map(|artifact| artifact.file.as_str()),
        Some("artifact.bin")
    );
    Ok(())
}

#[test]
fn legacy_evidence_sidecar_can_be_refreshed_to_the_declared_gzip_sidecar() -> TestResult {
    let fixture = Fixture::new()?;
    fs::create_dir(&fixture.output)?;
    fixture.write_output(&fixture.output, "complete", b"legacy-artifact")?;

    let legacy = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    assert!(
        legacy
            .reuse(&fixture.identity, Some(&fixture.input), false)
            .is_err()
    );

    legacy.publish(&fixture.identity, &Job::new("refresh"), |staging| {
        fixture.write_gzip_output(
            staging,
            "artifact.bin",
            b"refreshed-artifact",
            b"refreshed summary",
        )
    })?;

    let refreshed = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let reused = refreshed
        .reuse(&fixture.identity, Some(&fixture.input), true)?
        .ok_or("the refreshed gzip-sidecar result should be reusable")?;
    assert!(reused.complete);
    assert!(fixture.output.join("evidence.jsonl.gz").is_file());
    assert!(!fixture.output.join("evidence.jsonl").exists());
    Ok(())
}

#[test]
fn undeclared_legacy_evidence_sidecar_is_rejected_beside_a_gzip_sidecar() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish_with_gzip_evidence()?;
    fs::write(
        fixture.output.join("evidence.jsonl"),
        b"undeclared legacy sidecar",
    )?;

    assert!(ResultDirectory::inspect(&fixture.output, ResultKind::Extract).is_err());
    Ok(())
}

#[test]
fn gzip_evidence_sidecar_cannot_be_declared_as_an_artifact() -> TestResult {
    let fixture = Fixture::new()?;
    let destination = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let result = destination.publish(&fixture.identity, &Job::new("invalid sidecar"), |staging| {
        fixture.write_gzip_output(staging, "evidence.jsonl.gz", b"gzip-sidecar", b"summary")
    });

    assert!(result.is_err());
    assert!(!fixture.output.exists());
    Ok(())
}

#[test]
fn refine_result_identity_uses_the_ordered_manifest_source_set() -> TestResult {
    let root = tempfile::tempdir()?;
    let output = root.path().join("refined");
    let identity = publish_refine_result(&output)?;

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
