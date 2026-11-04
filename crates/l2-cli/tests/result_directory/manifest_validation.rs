use super::{
    ManifestArtifact, OutputFileStamp, OwnedManifest, ResultIdentity, ResultKind, ResultReceipt,
};
use l2_workbench::job::{Job, cache::SourceIdentity};
use std::error::Error;

fn stamp(file: String) -> OutputFileStamp {
    OutputFileStamp {
        file,
        byte_length: 1,
        sha256: Some("a".repeat(64)),
        device_id: None,
        file_id: None,
        modified_seconds: None,
        modified_nanoseconds: None,
        changed_seconds: None,
        changed_nanoseconds: None,
    }
}

#[test]
fn receipt_validation_matches_one_thousand_and_maximum_artifacts_in_any_order()
-> Result<(), Box<dyn Error>> {
    for count in [1_000, super::MAX_RESULT_ARTIFACTS] {
        let digest = "b".repeat(64);
        let artifacts: Vec<_> = (0..count)
            .map(|index| ManifestArtifact {
                file: format!("artifact-{index:05}.bin"),
                byte_length: 1,
                sha256: Some("a".repeat(64)),
            })
            .collect();
        let mut stamps: Vec<_> = artifacts
            .iter()
            .rev()
            .map(|artifact| stamp(artifact.file.clone()))
            .collect();
        stamps.push(stamp("summary.txt".to_owned()));
        let manifest = OwnedManifest {
            complete: true,
            artifacts,
            evidence_file: None,
            source_sha256s: Vec::new(),
            source_identity_sha256: Some(digest.clone()),
            source_labels: Vec::new(),
        };
        let receipt = ResultReceipt {
            schema_version: 1,
            identity: ResultIdentity {
                kind: ResultKind::Refine,
                algorithm_version: 1,
                source: SourceIdentity::from_sha256(digest.clone())?,
                settings: serde_json::json!({}),
            },
            complete: true,
            source_sha256s: Vec::new(),
            source_identity_sha256: Some(digest),
            job: Job::new("large receipt").snapshot()?,
            output_files: stamps,
        };
        super::validate_receipt(&receipt, &manifest, ResultKind::Refine)?;
        assert_eq!(manifest.artifacts.len(), count);
        assert_eq!(receipt.output_files.len(), count + 1);
    }
    Ok(())
}
