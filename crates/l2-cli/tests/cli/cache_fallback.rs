use std::{error::Error, fs, process::Command};

#[test]
fn refine_cache_fallback_stays_inside_json_progress_snapshots() -> Result<(), Box<dyn Error>> {
    let output = refine_with_unavailable_cache("json")?;

    assert!(
        matches!(output.status.code(), Some(0 | 3)),
        "refine failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr)?;
    let snapshots = stderr
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(!snapshots.is_empty(), "JSON progress emitted no snapshots");
    assert!(
        snapshots.iter().any(|snapshot| {
            snapshot
                .pointer("/cache_fallbacks/records")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|records| {
                    records.iter().any(|record| {
                        record.get("stage").and_then(serde_json::Value::as_str)
                            == Some("artifact_analysis")
                            && record.get("kind").and_then(serde_json::Value::as_str)
                                == Some("cache_unavailable")
                    })
                })
        }),
        "cache fallback was absent from structured progress: {stderr}"
    );
    Ok(())
}

#[test]
fn refine_cache_fallback_has_one_human_summary_line() -> Result<(), Box<dyn Error>> {
    let output = refine_with_unavailable_cache("never")?;

    assert!(
        matches!(output.status.code(), Some(0 | 3)),
        "refine failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr)?;
    let summaries = stderr
        .lines()
        .filter(|line| line.starts_with("Cache fallback summary:"))
        .collect::<Vec<_>>();
    let [summary] = summaries.as_slice() else {
        return Err(format!("expected one cache fallback summary; stderr: {stderr}").into());
    };
    assert!(summary.contains("artifact analysis cache unavailable x1"));
    assert!(summary.contains("persistent cache could not be opened"));
    Ok(())
}

fn refine_with_unavailable_cache(progress: &str) -> Result<std::process::Output, Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache_home = temporary.path().join("cache-home-file");
    let state_home = temporary.path().join("state-home");
    let input = temporary.path().join("input.bin");
    let output_directory = temporary.path().join("input.bin.refined");
    fs::write(&cache_home, b"not a cache directory")?;
    fs::create_dir(&state_home)?;
    fs::write(&input, b"ordinary file input")?;

    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("refine")
        .arg(&input)
        .arg("--output")
        .arg(&output_directory)
        .args(["--progress", progress])
        .env("XDG_CACHE_HOME", &cache_home)
        .env("XDG_STATE_HOME", &state_home)
        .output()?;
    Ok(output)
}
