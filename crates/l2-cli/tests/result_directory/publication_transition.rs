use super::{Fixture, TestResult};
use crate::{
    publish,
    result_directory::{ResultDirectory, ResultKind},
};
use l2_workbench::job::{
    Job, RecoveryPublicationSample, RecoveryPublicationSourceBasis, RecoveryTransitionOutcome,
    RecoveryTransitionSample, RecoveryTransitionStage, cache::SourceIdentity,
};
use std::{fs, io};

fn sample(job: &Job, outcome: RecoveryTransitionOutcome) -> TestResult<RecoveryPublicationSample> {
    let snapshot = job.snapshot()?;
    let record = snapshot
        .recovery_transitions
        .records()
        .iter()
        .find(|record| {
            record.stage() == RecoveryTransitionStage::Publication && record.outcome() == outcome
        })
        .ok_or("publication transition is missing")?;
    match record.sample() {
        Some(RecoveryTransitionSample::Publication(sample)) => Ok(*sample),
        _ => Err("publication identity sample is missing".into()),
    }
}

fn expected_source(fixture: &Fixture) -> TestResult<[u8; 32]> {
    match &fixture.identity.source {
        SourceIdentity::Sha256(digest) => l2_workbench::parse_sha256_digest(digest)
            .ok_or_else(|| "invalid fixture source digest".into()),
        _ => Err("fixture requires a full source digest".into()),
    }
}

#[test]
fn successful_atomic_publication_binds_the_exact_artifact_and_source() -> TestResult {
    let fixture = Fixture::new()?;
    let destination = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let job = Job::new("published result");
    let bytes = b"publication transition artifact";
    destination.publish(&fixture.identity, &job, |staging| {
        fixture.write_output(staging, "complete", bytes)
    })?;
    let sample = sample(&job, RecoveryTransitionOutcome::Published)?;
    assert_eq!(sample.source_set_sha256, Some(expected_source(&fixture)?));
    assert_eq!(
        sample.source_basis,
        RecoveryPublicationSourceBasis::StagedManifest
    );
    assert_eq!(sample.artifact_count, Some(1));
    let artifact = sample.artifact.ok_or("published artifact is missing")?;
    assert_eq!(
        artifact.sha256,
        l2_workbench::parse_sha256_digest(&l2_workbench::sha256(bytes))
            .ok_or("invalid artifact digest")?
    );
    assert_eq!(artifact.byte_length, u64::try_from(bytes.len())?);
    assert_eq!(fs::read(fixture.output.join("artifact.bin"))?, bytes);
    Ok(())
}

#[test]
fn failed_writer_reports_unpublished_without_claiming_an_artifact() -> TestResult {
    let fixture = Fixture::new()?;
    let destination = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let job = Job::new("failed result");
    let result = destination.publish(&fixture.identity, &job, |_staging| {
        Err::<(), _>(io::Error::other("synthetic writer failure").into())
    });
    assert!(result.is_err());
    assert!(!fixture.output.exists());
    let sample = sample(&job, RecoveryTransitionOutcome::PublicationFailed)?;
    assert_eq!(sample.source_set_sha256, Some(expected_source(&fixture)?));
    assert_eq!(
        sample.source_basis,
        RecoveryPublicationSourceBasis::RequestedIdentity
    );
    assert_eq!(sample.artifact, None);
    assert_eq!(sample.artifact_count, None);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn committed_directory_with_failed_parent_sync_is_reported_as_durability_uncertain() -> TestResult {
    let fixture = Fixture::new()?;
    let destination = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    let job = Job::new("uncertain durability");
    publish::test_hooks::TEST_FAULT
        .with(|slot| slot.set(Some(publish::test_hooks::TestFault::DirectorySync)));
    let bytes = b"committed before sync failure";
    let result = destination.publish(&fixture.identity, &job, |staging| {
        fixture.write_output(staging, "complete", bytes)
    });
    assert!(result.is_err());
    assert_eq!(fs::read(fixture.output.join("artifact.bin"))?, bytes);
    let sample = sample(
        &job,
        RecoveryTransitionOutcome::PublishedDurabilityUncertain,
    )?;
    assert_eq!(sample.source_set_sha256, Some(expected_source(&fixture)?));
    assert_eq!(
        sample.artifact.map(|artifact| artifact.sha256),
        l2_workbench::parse_sha256_digest(&l2_workbench::sha256(bytes))
    );
    Ok(())
}

#[test]
fn uncertain_replacement_is_typed_without_retaining_its_private_path() -> TestResult {
    let job = Job::new("uncertain replacement");
    let result: Result<(), publish::DirectoryPublishError> = Err(
        publish::DirectoryPublishError::PublishedReplacementUncertain {
            source: io::Error::other("synthetic replacement uncertainty"),
            retained_path: std::path::PathBuf::from("private-recovery-name"),
        },
    );
    let observation = crate::publication_transition::initial_sample(None);
    crate::publication_transition::record_result(&job, &result, observation);
    let recorded = sample(
        &job,
        RecoveryTransitionOutcome::PublishedReplacementUncertain,
    )?;
    assert_eq!(recorded.source_set_sha256, None);
    assert!(!serde_json::to_string(&job.snapshot()?)?.contains("private-recovery-name"));
    Ok(())
}
