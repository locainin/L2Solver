use crate::arguments::{RecoveryOptions, RefineOptions};
use l2_workbench::job::{Job, MemoryBudget};
use std::{error::Error, fs, path::Path};

#[test]
fn zip_members_are_omitted_when_their_archive_parent_cannot_be_published()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("source.zip");
    let output = directory.path().join("result");
    let png = super::structural_png()?;
    super::large_formats::write_archive_blocks(&input, 0x91, &png, 192)?;
    let length = fs::metadata(&input)?.len();
    let source_limit = crate::refine::read_budget::analysis_reservation(length)
        .ok_or("source read reservation overflows")?
        + 512 * 1024;
    let recovery = RecoveryOptions {
        no_cache: true,
        memory_limit: 8 * 1024 * 1024,
        source_read_limit: source_limit,
        ..RecoveryOptions::default()
    };
    assert_archive_was_extracted_without_output_room(&input, &recovery, &png)?;
    let options = RefineOptions {
        input,
        output: Some(output.clone()),
        dry_run: false,
        salvage: false,
        recovery,
    };
    assert!(!super::run(&options, &mut Vec::new())?);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    let artifacts = manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or("artifacts missing")?;
    assert!(!artifacts.iter().any(|artifact| {
        artifact
            .get("origins")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|origins| {
                origins.iter().any(|origin| {
                    origin
                        .pointer("/origin/kind")
                        .and_then(serde_json::Value::as_str)
                        == Some("archive_member")
                })
            })
    }), "member was published without its archive parent");
    let omissions = manifest
        .pointer("/sources/0/omissions")
        .and_then(serde_json::Value::as_array)
        .ok_or("source omissions missing")?;
    assert!(omissions.iter().any(|omission| {
        omission.get("kind").and_then(serde_json::Value::as_str)
            == Some("source_range_output_read_limit")
    }));
    assert!(omissions.iter().any(|omission| {
        omission.get("kind").and_then(serde_json::Value::as_str)
            == Some("source_archive_members_omitted")
            && omission
                .get("count")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|count| count >= 1)
    }));
    assert!(omissions.iter().any(|omission| {
        omission.get("kind").and_then(serde_json::Value::as_str)
            == Some("source_archive_member_omission")
            && omission
                .get("entry_index")
                .and_then(serde_json::Value::as_u64)
                == Some(0)
    }));
    Ok(())
}

fn assert_archive_was_extracted_without_output_room(
    path: &Path,
    recovery: &RecoveryOptions,
    png: &[u8],
) -> Result<(), Box<dyn Error>> {
    use crate::refine::{
        input::{prepare_input_set_with_limit, read_sources},
        policy::RefinePolicy,
        range_transform::StreamingBudget,
    };

    let memory = MemoryBudget::new(recovery.memory_limit);
    let job = Job::new("ZIP parent output admission");
    let input = prepare_input_set_with_limit(path, recovery.source_read_limit, &job, &memory)?;
    let policy = RefinePolicy::new(recovery, false)?;
    let sources = read_sources(
        &input,
        policy.total_input_limit,
        policy.per_file_limit,
        &job,
        &memory,
    )?;
    let source = sources.first().ok_or("source missing")?;
    assert!(source.bytes().is_none(), "fixture is not file-backed");
    let mut streaming = StreamingBudget::new(&policy, &sources)?;
    let observation = streaming.reserve_observation(source.length())?;
    streaming.begin_source()?;
    let mut options = policy.analyzer;
    options.limits.max_total_work_bytes = streaming.range_work_limit(
        source.length(),
        options.limits.max_total_work_bytes,
        recovery.profile,
    );
    let range = source.analyze_ranges(&input, 0, options, &job, &memory, observation.is_some())?;
    assert!(!range.retain_source, "archive output unexpectedly fits");
    let archive = range.archive.as_ref().ok_or("archive was not inspected")?;
    assert!(
        archive
            .entries
            .iter()
            .any(|entry| entry.content.as_deref() == Some(png)),
        "the independent parser did not extract the PNG member"
    );
    Ok(())
}
