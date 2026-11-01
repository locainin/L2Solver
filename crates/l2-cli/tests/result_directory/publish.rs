//! Explicit replacement preserves ownership checks even when the source changes

use super::{Fixture, TestResult};
use crate::result_directory::{ResultDirectory, ResultKind};
use l2_workbench::job::{Job, cache::SourceIdentity};
use std::{fs, io};

#[test]
fn explicit_refresh_atomically_replaces_an_owned_result_from_another_source() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.publish("complete", b"previous-artifact")?;
    fs::write(&fixture.input, b"different-capture-input")?;
    fixture.identity.source = SourceIdentity::sha256_file(&fixture.input)?;
    let destination = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;

    // Ordinary reuse cannot reinterpret the old collection as a result of the new input
    assert!(
        destination
            .reuse(
                &fixture.identity,
                Some(&fixture.input),
                false,
                &Job::new("reuse")
            )
            .is_err()
    );
    destination.publish(
        &fixture.identity,
        &Job::new("explicit refresh"),
        |staging| fixture.write_output(staging, "complete", b"replacement-artifact"),
    )?;

    let replacement = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    assert!(
        replacement
            .reuse(
                &fixture.identity,
                Some(&fixture.input),
                true,
                &Job::new("reuse")
            )?
            .is_some_and(|result| result.complete)
    );
    assert_eq!(
        fs::read(fixture.output.join("artifact.bin"))?,
        b"replacement-artifact"
    );
    Ok(())
}

#[test]
fn failed_refresh_from_another_source_preserves_the_previous_collection() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.publish("complete", b"previous-artifact")?;
    let previous_identity = fixture.identity.clone();
    let previous_manifest = fs::read(fixture.output.join("manifest.json"))?;
    fs::write(&fixture.input, b"different-capture-input")?;
    fixture.identity.source = SourceIdentity::sha256_file(&fixture.input)?;
    let destination = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;

    let result = destination.publish(
        &fixture.identity,
        &Job::new("explicit refresh"),
        |staging| {
            fixture.write_output(staging, "partial", b"unfinished-replacement")?;
            Err::<(), _>(io::Error::other("replacement computation failed").into())
        },
    );

    assert!(result.is_err());
    assert_eq!(
        fs::read(fixture.output.join("manifest.json"))?,
        previous_manifest
    );
    assert_eq!(
        fs::read(fixture.output.join("artifact.bin"))?,
        b"previous-artifact"
    );
    // The output still has its original identity even though the input path now changed
    let previous = ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    assert!(
        previous
            .reuse(&previous_identity, None, true, &Job::new("reuse"))?
            .is_some_and(|result| result.complete)
    );
    Ok(())
}
