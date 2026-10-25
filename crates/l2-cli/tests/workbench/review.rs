use super::support::{path_arg, run};
use l2_workbench::{
    evidence::Case,
    journal::{Event, Hypothesis, Journal, JournalOptions},
};
use serde_json::{Value, json};
use std::{error::Error, fs};

#[test]
fn common_models_without_active_content() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let directory = temp.path().join("journal");
    fs::create_dir(&directory)?;
    let mut journal = Journal::create(&directory, &Case::new(), JournalOptions::default())?;
    for value in ["<script>candidate</script>", "second candidate"] {
        journal.record(&Hypothesis {
            title: value.into(),
            input: json!({"value":value}),
            operation: json!({"kind":"inspect"}),
            assumptions: vec!["Needs an independent check".into()],
        })?;
    }
    drop(journal);
    let result = run(
        &[
            "review",
            path_arg(&directory)?,
            "--limit",
            "1",
            "--format",
            "html",
        ],
        b"",
    )?;
    assert_eq!(
        result.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let html = String::from_utf8(result.stdout)?;
    assert!(!html.contains("<script>"));
    assert!(html.contains("Hypotheses"));
    assert!(html.contains("omitted"));
    assert!(html.contains("Legacy-unverified checks remain in history"));
    assert!(html.contains("stored metadata, not a signature"));
    let text = run(&["review", path_arg(&directory)?, "--format", "text"], b"")?;
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout)?;
    assert!(text.contains("Legacy-unverified checks remain in history"));
    assert!(text.contains("stored metadata, not a signature"));
    let result = run(&["review", path_arg(&directory)?, "--format", "json"], b"")?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(report.pointer("/journal/hypotheses"), Some(&json!(2)));
    assert_eq!(report.get("omitted_hypotheses"), Some(&json!(0)));
    assert!(
        report
            .get("carrier_results")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    );
    Ok(())
}

#[test]
fn common_unreadable_result_store_publication() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let directory = temp.path().join("journal");
    fs::create_dir(&directory)?;
    drop(Journal::create(
        &directory,
        &Case::new(),
        JournalOptions::default(),
    )?);
    let missing = temp.path().join("missing-results");
    let output = temp.path().join("review.html");
    let result = run(
        &[
            "review",
            path_arg(&directory)?,
            "--carrier-results",
            path_arg(&missing)?,
            "--output",
            path_arg(&output)?,
        ],
        b"",
    )?;
    assert!(!result.status.success());
    assert!(!output.exists());
    Ok(())
}

#[test]
fn html_bounds_associations_json_observations() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let directory = temp.path().join("journal");
    fs::create_dir(&directory)?;
    let mut journal = Journal::create(&directory, &Case::new(), JournalOptions::default())?;
    for packet in 1..=3 {
        journal.record_event(&Event {
            source: "capture".into(),
            scope: "lan".into(),
            packet,
            kind: "packet_tcp".into(),
            actor: Some(format!("192.0.2.{packet}")),
            peer: None,
            clock: None,
            ticks: None,
            fields: json!({"source_mac":"02:00:00:00:00:01"}),
            ranges: Vec::new(),
        })?;
    }
    drop(journal);
    let output = run(
        &[
            "review",
            path_arg(&directory)?,
            "--limit",
            "1",
            "--format",
            "html",
        ],
        b"",
    )?;
    assert_eq!(output.status.code(), Some(3));
    let html = String::from_utf8(output.stdout)?;
    assert!(html.contains("192.0.2.1"));
    assert!(!html.contains("192.0.2.3"));
    assert!(html.contains("header_associations_omitted"));
    let output = run(
        &[
            "review",
            path_arg(&directory)?,
            "--limit",
            "1",
            "--format",
            "json",
        ],
        b"",
    )?;
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        report
            .pointer("/correlation/header_associations")
            .and_then(Value::as_array)
            .ok_or("missing associations")?
            .len(),
        3
    );
    assert!(
        report
            .pointer("/correlation/groups")
            .and_then(Value::as_array)
            .ok_or("missing groups")?
            .is_empty()
    );
    Ok(())
}

#[test]
fn html_truncated_association_preview_incomplete() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let directory = temp.path().join("journal");
    fs::create_dir(&directory)?;
    let mut journal = Journal::create(&directory, &Case::new(), JournalOptions::default())?;
    journal.record_event(&Event {
        source: "capture".into(),
        scope: "lan".into(),
        packet: 1,
        kind: "packet_tcp".into(),
        actor: Some("192.0.2.1".into()),
        peer: Some("192.0.2.2".into()),
        clock: None,
        ticks: None,
        fields: json!({
            "source_mac":"02:00:00:00:00:01",
            "destination_mac":"02:00:00:00:00:02"
        }),
        ranges: Vec::new(),
    })?;
    drop(journal);

    let output = run(
        &[
            "review",
            path_arg(&directory)?,
            "--limit",
            "1",
            "--format",
            "html",
        ],
        b"",
    )?;
    assert_eq!(output.status.code(), Some(3));
    let html = String::from_utf8(output.stdout)?;
    assert!(html.contains("View complete: false"));
    assert!(html.contains("Investigation review complete=false"));
    assert!(html.contains("header_associations_omitted"));
    Ok(())
}

#[test]
fn review_defaults_text_preserves_html() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let directory = temp.path().join("journal");
    fs::create_dir(&directory)?;
    drop(Journal::create(
        &directory,
        &Case::new(),
        JournalOptions::default(),
    )?);

    let output = run(&["review", path_arg(&directory)?], b"")?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.starts_with("Investigation review complete=true"));
    assert!(!text.starts_with("<!doctype html>"));

    let output = run(&["review", path_arg(&directory)?, "--format", "html"], b"")?;
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)?.starts_with("<!doctype html>"));
    Ok(())
}
