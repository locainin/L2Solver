use super::{Fixture, ResultKind, TestResult};
use l2_workbench::job::{
    Counter, Job,
    cache::{SourceFingerprint, SourceIdentity},
};
use std::fs;

const SOURCE_LENGTH: usize = 256 * 1024;

fn large_source() -> TestResult<Fixture> {
    let mut fixture = Fixture::new()?;
    fs::write(&fixture.input, vec![37_u8; SOURCE_LENGTH])?;
    fixture.identity.source = SourceIdentity::sha256_file(&fixture.input)?;
    Ok(fixture)
}

fn published_large_source() -> TestResult<Fixture> {
    let fixture = large_source()?;
    fixture.publish("complete", b"published artifact")?;
    Ok(fixture)
}

fn published_fast_source() -> TestResult<(Fixture, super::ResultIdentity)> {
    let fixture = large_source()?;
    let mut identity = fixture.identity.clone();
    identity.source = SourceIdentity::Fast(SourceFingerprint::fast(&fixture.input)?);
    super::inspect(&fixture.output, ResultKind::Extract)?.publish(
        &identity,
        &Job::new("publish"),
        |staging| fixture.write_output(staging, "complete", b"published artifact"),
    )?;
    Ok((fixture, identity))
}

#[test]
fn default_reuse_hashes_matching_sources_once() -> TestResult {
    let strong = published_large_source()?;
    let (fast, fast_identity) = published_fast_source()?;
    for (fixture, identity) in [(&strong, &strong.identity), (&fast, &fast_identity)] {
        let existing = super::inspect(&fixture.output, ResultKind::Extract)?;
        let job = Job::new("source verification");
        let mut reads = Vec::new();
        assert!(
            super::super::reuse::reuse_with_source_observer(
                &existing,
                identity,
                Some(&fixture.input),
                false,
                &job,
                |count| reads.push(count),
            )?
            .is_some()
        );
        assert!(reads.iter().all(|&count| count <= 64 * 1024));
        assert_eq!(reads.iter().sum::<usize>(), SOURCE_LENGTH);
        assert_eq!(
            job.snapshot()?.counters.get(&Counter::SourceReadBytes),
            Some(&(u64::try_from(SOURCE_LENGTH)?))
        );
    }
    Ok(())
}

#[test]
fn default_reuse_cancels_during_matching_source_hash() -> TestResult {
    let (fixture, identity) = published_fast_source()?;
    let existing = super::inspect(&fixture.output, ResultKind::Extract)?;
    let job = Job::new("cancel source verification");
    let result = super::super::reuse::reuse_with_source_observer(
        &existing,
        &identity,
        Some(&fixture.input),
        false,
        &job,
        |count| {
            if count > 0 {
                job.request_cancel();
            }
        },
    );
    assert!(result.is_err());
    assert!(job.is_cancelled());
    assert_eq!(
        job.snapshot()?.counters.get(&Counter::SourceReadBytes),
        Some(&(64 * 1024))
    );
    Ok(())
}

#[test]
fn inputless_reuse_requires_strong_identity() -> TestResult {
    let (fixture, identity) = published_fast_source()?;
    let existing = super::inspect(&fixture.output, ResultKind::Extract)?;
    assert!(
        existing
            .reuse(&identity, None, false, &Job::new("reuse"))
            .is_err()
    );
    assert!(
        existing
            .reuse(&fixture.identity, None, false, &Job::new("reuse"))?
            .is_some()
    );
    let mut different = fixture.identity;
    different.source = SourceIdentity::from_sha256("0".repeat(64))?;
    assert!(
        existing
            .reuse(&different, None, false, &Job::new("reuse"))
            .is_err()
    );
    Ok(())
}

#[test]
fn strict_and_default_reuse_cancel_after_one_source_chunk() -> TestResult {
    for strict in [true, false] {
        let fixture = published_large_source()?;
        let existing = super::inspect(&fixture.output, ResultKind::Extract)?;
        let mut identity = fixture.identity.clone();
        if !strict {
            identity.source = SourceIdentity::Fast(SourceFingerprint::fast(&fixture.input)?);
        }
        let manifest_before = fs::read(fixture.output.join("manifest.json"))?;
        let artifact_before = fs::read(fixture.output.join("artifact.bin"))?;
        let job = Job::new("cancel during source verification");
        let result = super::super::reuse::reuse_with_source_observer(
            &existing,
            &identity,
            Some(&fixture.input),
            strict,
            &job,
            |count| {
                if count > 0 {
                    job.request_cancel();
                }
            },
        );
        assert!(
            result.is_err(),
            "source hashing ignored cancellation in strict={strict}"
        );
        assert!(job.is_cancelled());
        assert_eq!(
            job.snapshot()?.counters.get(&Counter::SourceReadBytes),
            Some(&(64 * 1024))
        );
        assert_eq!(
            fs::read(fixture.output.join("manifest.json"))?,
            manifest_before
        );
        assert_eq!(
            fs::read(fixture.output.join("artifact.bin"))?,
            artifact_before
        );
    }
    Ok(())
}

#[test]
fn strict_and_default_reuse_reject_changed_source() -> TestResult {
    for strict in [true, false] {
        let fixture = published_large_source()?;
        let existing = super::inspect(&fixture.output, ResultKind::Extract)?;
        let mut identity = fixture.identity.clone();
        if !strict {
            identity.source = SourceIdentity::Fast(SourceFingerprint::fast(&fixture.input)?);
        }
        let job = Job::new("source verification");
        assert!(
            existing
                .reuse(&identity, Some(&fixture.input), strict, &job)?
                .is_some()
        );
        assert_eq!(
            job.snapshot()?.counters.get(&Counter::SourceReadBytes),
            Some(&(u64::try_from(SOURCE_LENGTH)?))
        );

        fs::write(&fixture.input, vec![38_u8; SOURCE_LENGTH])?;
        let changed_job = Job::new("changed source");
        assert!(
            existing
                .reuse(&identity, Some(&fixture.input), strict, &changed_job)
                .is_err()
        );
        assert_eq!(
            changed_job
                .snapshot()?
                .counters
                .get(&Counter::SourceReadBytes),
            Some(&(u64::try_from(SOURCE_LENGTH)?))
        );
    }
    Ok(())
}

#[test]
fn changed_fast_fingerprint_reads_full_source_once() -> TestResult {
    let (fixture, fast_identity) = published_fast_source()?;
    let bytes = fs::read(&fixture.input)?;
    let previous = fixture.input.with_extension("previous");
    fs::rename(&fixture.input, previous)?;
    fs::write(&fixture.input, bytes)?;
    let existing = super::inspect(&fixture.output, ResultKind::Extract)?;
    let job = Job::new("source fallback");
    assert!(
        existing
            .reuse(&fast_identity, Some(&fixture.input), false, &job)?
            .is_some()
    );
    assert_eq!(
        job.snapshot()?.counters.get(&Counter::SourceReadBytes),
        Some(&(u64::try_from(SOURCE_LENGTH)?))
    );
    Ok(())
}

#[test]
fn corrupt_artifact_receipts_remain_rejected_before_reuse() -> TestResult {
    for corruption in ["missing", "duplicate", "length", "digest"] {
        let fixture = published_large_source()?;
        let mut manifest = super::read_manifest(&fixture.output)?;
        match corruption {
            "missing" => {
                let stamps = super::json_field_mut(&mut manifest, "/l2solver_result/output_files")?
                    .as_array_mut()
                    .ok_or("output stamps are missing")?;
                stamps.retain(|stamp| {
                    stamp.get("file").and_then(serde_json::Value::as_str) != Some("artifact.bin")
                });
            }
            "duplicate" => {
                let stamps = super::json_field_mut(&mut manifest, "/l2solver_result/output_files")?
                    .as_array_mut()
                    .ok_or("output stamps are missing")?;
                let duplicate = stamps
                    .iter()
                    .find(|stamp| {
                        stamp.get("file").and_then(serde_json::Value::as_str)
                            == Some("artifact.bin")
                    })
                    .ok_or("artifact stamp is missing")?
                    .clone();
                stamps.push(duplicate);
            }
            "length" => {
                *super::json_field_mut(&mut manifest, "/artifacts/0/byte_length")? =
                    serde_json::json!(999);
            }
            "digest" => {
                super::json_field_mut(&mut manifest, "/artifacts/0")?
                    .as_object_mut()
                    .ok_or("artifact record is missing")?
                    .insert("sha256".to_owned(), serde_json::json!("a".repeat(64)));
            }
            _ => return Err("unknown corruption fixture".into()),
        }
        super::write_manifest(&fixture.output, &manifest)?;
        assert!(
            super::inspect(&fixture.output, ResultKind::Extract).is_err(),
            "accepted {corruption} receipt"
        );
    }
    Ok(())
}

#[test]
fn publication_uses_each_artifact_digest_when_manifest_order_differs_from_file_order() -> TestResult
{
    let fixture = Fixture::new()?;
    let job = Job::new("publish unsorted artifacts");
    super::inspect(&fixture.output, ResultKind::Extract)?.publish(
        &fixture.identity,
        &job,
        |staging| {
            fixture.write_output(staging, "complete", b"first")?;
            let mut manifest = super::read_manifest(staging)?;
            let artifacts = super::json_field_mut(&mut manifest, "/artifacts")?
                .as_array_mut()
                .ok_or("artifact records are missing")?;
            *artifacts = [
                ("z-last.bin", &b"last"[..]),
                ("artifact.bin", &b"first"[..]),
                ("a-first.bin", &b"start"[..]),
            ]
            .into_iter()
            .map(|(name, bytes)| {
                fs::write(staging.join(name), bytes)?;
                Ok(serde_json::json!({
                    "file": name,
                    "byte_length": bytes.len(),
                    "sha256": l2_workbench::sha256(bytes),
                    "provenance": [],
                }))
            })
            .collect::<Result<Vec<_>, std::io::Error>>()?;
            super::write_manifest(staging, &manifest)?;
            Ok(())
        },
    )?;
    let existing = super::inspect(&fixture.output, ResultKind::Extract)?;
    let reused = existing
        .reuse(
            &fixture.identity,
            Some(&fixture.input),
            false,
            &Job::new("reuse"),
        )?
        .ok_or("published result should be reusable")?;
    assert_eq!(reused.artifact_count, 3);
    assert_eq!(job.snapshot()?.counters.get(&Counter::Bytes), Some(&7));
    Ok(())
}
