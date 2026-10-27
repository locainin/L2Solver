use std::{
    error::Error,
    fs,
    path::Path,
    process::{Command, Output},
};

#[derive(Clone, Copy, Debug)]
enum RecoveryCommand {
    Extract,
    Refine,
}

#[test]
fn unavailable_cache_falls_back_for_extract_and_refine() -> Result<(), Box<dyn Error>> {
    for command in [RecoveryCommand::Extract, RecoveryCommand::Refine] {
        for bad_state in [false, true] {
            let temporary = tempfile::tempdir()?;
            let (output, destination) =
                run_with_unavailable_cache(temporary.path(), command, bad_state, &[])?;
            assert_recovery_succeeded(&output, &destination);
            let stderr = String::from_utf8(output.stderr)?;
            let expected_stage = match command {
                RecoveryCommand::Extract => "capture index",
                RecoveryCommand::Refine => "artifact analysis",
            };
            assert!(
                stderr.contains(&format!("{expected_stage} cache unavailable x1")),
                "{command:?}: {stderr}"
            );
            assert!(
                !stderr.contains(&temporary.path().display().to_string()),
                "cache paths must not enter fallback diagnostics: {stderr}"
            );
        }
    }
    Ok(())
}

#[test]
fn strict_cache_rejects_unavailable_cache_before_publication() -> Result<(), Box<dyn Error>> {
    for command in [RecoveryCommand::Extract, RecoveryCommand::Refine] {
        for bad_state in [false, true] {
            let temporary = tempfile::tempdir()?;
            let (output, destination) = run_with_unavailable_cache(
                temporary.path(),
                command,
                bad_state,
                &["--strict-cache"],
            )?;
            assert_eq!(
                output.status.code(),
                Some(1),
                "{command:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                !destination.exists(),
                "{command:?} published despite a strict cache error"
            );
        }
    }
    Ok(())
}

#[test]
fn no_cache_and_refine_dry_run_ignore_unavailable_cache_even_in_strict_mode()
-> Result<(), Box<dyn Error>> {
    for command in [RecoveryCommand::Extract, RecoveryCommand::Refine] {
        let temporary = tempfile::tempdir()?;
        let (output, destination) = run_with_unavailable_cache(
            temporary.path(),
            command,
            false,
            &["--strict-cache", "--no-cache"],
        )?;
        assert_recovery_succeeded(&output, &destination);
        assert!(!String::from_utf8(output.stderr)?.contains("Cache fallback summary:"));
    }
    let temporary = tempfile::tempdir()?;
    let (output, destination) = run_with_unavailable_cache(
        temporary.path(),
        RecoveryCommand::Refine,
        false,
        &["--strict-cache", "--dry-run"],
    )?;
    assert!(
        matches!(output.status.code(), Some(0 | 3)),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!destination.exists(), "dry run published output");
    assert!(!String::from_utf8(output.stderr)?.contains("Cache fallback summary:"));
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum CheckpointFailure {
    Start,
    Finish,
}

#[test]
fn checkpoint_write_failures_follow_the_cache_policy() -> Result<(), Box<dyn Error>> {
    for command in [RecoveryCommand::Extract, RecoveryCommand::Refine] {
        for failure in [CheckpointFailure::Start, CheckpointFailure::Finish] {
            for strict in [false, true] {
                let temporary = tempfile::tempdir()?;
                let (output, destination) = run_with_failing_checkpoint(
                    temporary.path(),
                    command,
                    failure,
                    strict,
                    "never",
                )?;
                let stderr = String::from_utf8_lossy(&output.stderr);
                if strict {
                    assert_eq!(
                        output.status.code(),
                        Some(1),
                        "{command:?} {failure:?}: {stderr}"
                    );
                    assert_eq!(
                        destination.join("manifest.json").is_file(),
                        matches!(failure, CheckpointFailure::Finish)
                    );
                    assert!(stderr.contains("checkpoint write rejected"), "{stderr}");
                    assert!(
                        !stderr.contains('\x1b'),
                        "raw control character reached stderr: {stderr:?}"
                    );
                    assert!(
                        stderr.contains("\\u{1b}"),
                        "control character was not escaped: {stderr:?}"
                    );
                } else {
                    assert_recovery_succeeded(&output, &destination);
                    assert!(
                        stderr.contains("checkpoint cache unavailable x1"),
                        "{command:?} {failure:?}: {stderr}"
                    );
                    assert!(
                        !stderr.contains("checkpoint write rejected"),
                        "fallback diagnostics must not retain database error text: {stderr}"
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn checkpoint_failure_appears_in_bounded_json_progress() -> Result<(), Box<dyn Error>> {
    for command in [RecoveryCommand::Extract, RecoveryCommand::Refine] {
        let temporary = tempfile::tempdir()?;
        let (output, destination) = run_with_failing_checkpoint(
            temporary.path(),
            command,
            CheckpointFailure::Finish,
            false,
            "json",
        )?;
        assert_recovery_succeeded(&output, &destination);
        let stderr = String::from_utf8(output.stderr)?;
        let snapshots = stderr
            .lines()
            .map(serde_json::from_str::<serde_json::Value>)
            .collect::<Result<Vec<_>, _>>()?;
        let mut records = snapshots
            .iter()
            .filter_map(|snapshot| snapshot.pointer("/cache_fallbacks/records"))
            .filter_map(serde_json::Value::as_array)
            .flatten();
        assert!(
            records.any(|record| {
                record.get("stage").and_then(serde_json::Value::as_str) == Some("checkpoint")
                    && record.get("kind").and_then(serde_json::Value::as_str)
                        == Some("cache_unavailable")
                    && record
                        .get("sample_detail")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|sample| sample.is_ascii() && sample.len() <= 160)
            }),
            "checkpoint fallback missing from structured progress: {stderr}"
        );
    }
    Ok(())
}

fn run_with_failing_checkpoint(
    root: &Path,
    command: RecoveryCommand,
    failure: CheckpointFailure,
    strict: bool,
    progress: &str,
) -> Result<(Output, std::path::PathBuf), Box<dyn Error>> {
    let cache_home = root.join("cache");
    let state_home = root.join("state");
    fs::create_dir(&cache_home)?;
    fs::create_dir(&state_home)?;
    drop(l2_workbench::job::cache::Cache::open_at(
        cache_home.join("l2solver"),
        state_home.join("l2solver"),
        1024 * 1024,
    )?);
    let connection = rusqlite::Connection::open(state_home.join("l2solver").join("cache.sqlite3"))?;
    let trigger = match failure {
        CheckpointFailure::Start => {
            "CREATE TRIGGER reject_checkpoint BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(ABORT, 'checkpoint write rejected \x1b[31m'); END;"
        }
        CheckpointFailure::Finish => {
            "CREATE TRIGGER reject_checkpoint BEFORE UPDATE ON checkpoints WHEN NEW.status = 2 BEGIN SELECT RAISE(ABORT, 'checkpoint write rejected \x1b[31m'); END;"
        }
    };
    connection.execute_batch(trigger)?;
    drop(connection);
    let flags: &[&str] = if strict { &["--strict-cache"] } else { &[] };
    run_command(root, command, progress, flags)
}

fn run_with_unavailable_cache(
    root: &Path,
    command: RecoveryCommand,
    bad_state: bool,
    flags: &[&str],
) -> Result<(Output, std::path::PathBuf), Box<dyn Error>> {
    let cache_home = root.join("cache");
    let state_home = root.join("state");
    for (path, invalid) in [(&cache_home, !bad_state), (&state_home, bad_state)] {
        if invalid {
            fs::write(path, b"not a directory")?;
        } else {
            fs::create_dir(path)?;
        }
    }
    run_command(root, command, "never", flags)
}

fn run_command(
    root: &Path,
    command: RecoveryCommand,
    progress: &str,
    flags: &[&str],
) -> Result<(Output, std::path::PathBuf), Box<dyn Error>> {
    let source = root.join("source");
    let destination = root.join("result");
    let verb = write_source(command, &source)?;
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg(verb)
        .arg(source)
        .arg("--output")
        .arg(&destination)
        .args(["--progress", progress])
        .args(flags)
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("XDG_STATE_HOME", root.join("state"))
        .output()?;
    Ok((output, destination))
}

fn assert_recovery_succeeded(output: &Output, destination: &Path) {
    assert!(
        matches!(output.status.code(), Some(0 | 3)),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        destination.join("manifest.json").is_file(),
        "result was not published"
    );
}

fn write_source(command: RecoveryCommand, source: &Path) -> Result<&'static str, Box<dyn Error>> {
    Ok(match command {
        RecoveryCommand::Extract => {
            let mut capture = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
            capture.extend_from_slice(&[0; 8]);
            capture.extend_from_slice(&l2_pcap::MAX_FRAME_LENGTH.to_le_bytes());
            capture.extend_from_slice(&1_u32.to_le_bytes());
            fs::write(source, capture)?;
            "extract"
        }
        RecoveryCommand::Refine => {
            fs::write(source, b"ordinary file input")?;
            "refine"
        }
    })
}
