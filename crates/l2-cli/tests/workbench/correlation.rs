use super::support::{path_arg, run};
use l2_workbench::{
    evidence::Case,
    journal::{Event, Journal, JournalOptions},
};
use serde_json::{Value, json};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Output,
};

#[test]
fn correlation_cli_bindings_event_omissions() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let (directory, plan) = create_correlation_fixture(temp.path())?;

    let output = run_correlation(&directory, &plan, Some("json"), true)?;
    assert_json_omission_output(&output)?;

    let output = run_correlation(&directory, &plan, None, true)?;
    assert_text_omission_output(output)?;

    let output = run_correlation(&directory, &plan, Some("html"), false)?;
    assert_escaped_html_output(output)?;

    Ok(())
}

fn create_correlation_fixture(root: &Path) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let directory = root.join("journal");
    fs::create_dir(&directory)?;
    let mut journal = Journal::create(&directory, &Case::new(), JournalOptions::default())?;
    for packet in [1, 2] {
        journal.record_event(&Event {
            source: "capture".into(),
            scope: "vlan-9".into(),
            packet,
            kind: "packet_tcp".into(),
            actor: Some("192.0.2.7".into()),
            peer: None,
            clock: Some("clock".into()),
            ticks: Some(packet),
            fields: json!({}),
            ranges: Vec::new(),
        })?;
    }
    drop(journal);
    let plan = root.join("plan.json");
    fs::write(
        &plan,
        serde_json::to_vec(
            &json!({"bindings":[{"id":"lease","source":"capture","scope":"vlan-9","subject":"192.0.2.7","identity":"<device>","first_packet":1,"last_packet":2,"origin_claim":"supplied lease","evidence":[{"source":"lease-document","offset":0,"length":1,"packet":null}]}]}),
        )?,
    )?;
    Ok((directory, plan))
}

fn run_correlation(
    directory: &Path,
    plan: &Path,
    format: Option<&str>,
    limit_events: bool,
) -> Result<Output, Box<dyn Error>> {
    let directory = path_arg(directory)?;
    let plan = path_arg(plan)?;
    let mut args = vec!["correlate", directory, "--plan", plan];
    if limit_events {
        args.extend(["--max-events", "1"]);
    }
    if let Some(format) = format {
        args.extend(["--format", format]);
    }
    run(&args, b"")
}

fn assert_json_omission_output(output: &Output) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.get("omitted_events"), Some(&json!(1)));
    assert_eq!(
        report.pointer("/groups/0/identity"),
        Some(&json!("<device>"))
    );
    Ok(())
}

fn assert_text_omission_output(output: Output) -> Result<(), Box<dyn Error>> {
    assert_eq!(output.status.code(), Some(3));
    let text = String::from_utf8(output.stdout)?;
    assert!(text.starts_with("events=1 omitted=1"));
    assert!(text.contains("identity=<device>"));
    Ok(())
}

fn assert_escaped_html_output(output: Output) -> Result<(), Box<dyn Error>> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let html = String::from_utf8(output.stdout)?;
    assert!(html.contains("&lt;device&gt;"));
    assert!(!html.contains("<device>"));
    Ok(())
}

#[test]
fn invalid_correlation_plan_rejected() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let directory = temp.path().join("journal");
    fs::create_dir(&directory)?;
    drop(Journal::create(
        &directory,
        &Case::new(),
        JournalOptions::default(),
    )?);
    let plan = temp.path().join("bad-plan.json");
    fs::write(&plan, br#"{"bindings":[],"unknown":true}"#)?;
    let report = temp.path().join("report.html");
    let output = run(
        &[
            "correlate",
            path_arg(&directory)?,
            "--plan",
            path_arg(&plan)?,
            "--format",
            "html",
            "--output",
            path_arg(&report)?,
        ],
        b"",
    )?;
    assert!(!output.status.success());
    assert!(!report.exists());
    Ok(())
}
