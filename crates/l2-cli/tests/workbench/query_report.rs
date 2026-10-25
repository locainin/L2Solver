use super::support::{path_arg, run};
use l2_workbench::{
    evidence::{Case, Edge, EvidenceStatus, SourceRange},
    sha256,
};
use serde_json::{Value, json};
use std::{error::Error, fs};

fn evidence_case() -> Result<Case, Box<dyn Error>> {
    let mut case = Case::new();
    let source = case.add_source("capture.pcap", "capture", 64, &sha256(b"source-a"), None)?;
    let other = case.add_source("other.pcap", "capture", 64, &sha256(b"source-b"), None)?;
    let ranges = vec![
        SourceRange {
            source: source.clone(),
            packet: Some(3),
            offset: 8,
            length: 3,
        },
        SourceRange {
            source,
            packet: Some(4),
            offset: 16,
            length: 3,
        },
        SourceRange {
            source: other,
            packet: Some(3),
            offset: 24,
            length: 3,
        },
    ];
    let input = case.add_bytes_node(
        "candidate",
        b"abc",
        ranges,
        json!({"operation":"literal comparison"}),
    )?;
    let result = case.add_node(
        "candidate_result",
        None,
        Vec::new(),
        json!({"explanation":"Requires independent validation"}),
    )?;
    case.add_edge(Edge {
        from: input,
        to: result,
        relation: "tested_against".to_owned(),
        status: EvidenceStatus::ConstraintFailed,
        reason: "One held-out observation contradicts the requirement".to_owned(),
    })?;
    Ok(case)
}

#[test]
fn query_defaults_text() -> Result<(), Box<dyn Error>> {
    let output = run(&["query", "-"], &evidence_case()?.to_json()?)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout)?;
    assert!(report.starts_with("Evidence query:"), "{report}");
    assert!(report.contains("Node 1 kind=candidate"), "{report}");
    Ok(())
}

#[test]
fn json_query_qualified_packet_filters() -> Result<(), Box<dyn Error>> {
    let case = evidence_case()?;
    let output = run(
        &[
            "query",
            "-",
            "--filter",
            "kind=candidate",
            "--format",
            "json",
        ],
        &case.to_json()?,
    )?;
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        report.pointer("/matches/0/details/operation"),
        Some(&json!("literal comparison"))
    );
    assert_eq!(
        report.pointer("/matches/0/relations/0/status"),
        Some(&json!("constraint_failed"))
    );
    assert_eq!(
        report.pointer("/matches/0/blob"),
        Some(&json!(format!("sha256:{}", sha256(b"abc"))))
    );
    let filters = report
        .pointer("/matches/0/packet_filters")
        .and_then(Value::as_array)
        .ok_or("missing packet filters")?;
    assert_eq!(filters.len(), 2);
    let first = filters
        .iter()
        .find(|value| {
            value.get("source_id") == Some(&json!(format!("sha256:{}", sha256(b"source-a"))))
        })
        .ok_or("missing source-a filter")?;
    assert_eq!(
        first.get("expression"),
        Some(&json!("frame.number in {3, 4}"))
    );
    assert_eq!(
        report.pointer("/sources/0/label"),
        Some(&json!("capture.pcap"))
    );
    Ok(())
}

#[test]
fn text_query_source_ranges_coverage() -> Result<(), Box<dyn Error>> {
    let output = run(
        &["query", "-", "--format", "text"],
        &evidence_case()?.to_json()?,
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout)?;
    for text in [
        "matched=2",
        "omitted=0",
        "candidate_result",
        "constraint_failed",
        "literal comparison",
        "held-out",
        "Wireshark-compatible display filter",
        "expression=frame.number in {3, 4}",
        "offset=8 length=3",
        "capture.pcap",
    ] {
        assert!(report.contains(text), "missing {text}: {report}");
    }
    assert!(!report.contains("Wireshark source="), "{report}");
    Ok(())
}

#[test]
fn html_query_without_active_content() -> Result<(), Box<dyn Error>> {
    let mut case = evidence_case()?;
    case.add_node(
        "hostile_text",
        None,
        Vec::new(),
        json!({"value":"<script>alert('x')</script>&", "terminal":"\u{1b}[31m"}),
    )?;
    let output = run(&["query", "-", "--format", "html"], &case.to_json()?)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout)?;
    assert!(report.starts_with("<!doctype html>"));
    assert!(report.contains("L2Solver evidence query"));
    assert!(report.contains("href=\"#kind-"));
    assert!(report.contains("<details"));
    assert!(report.contains("<details><summary>Sources and coverage notes</summary>"));
    assert!(report.contains("frame.number in {3, 4}"));
    assert!(report.contains("&lt;script&gt;"));
    assert!(!report.contains("<script>"));
    assert!(report.contains("Content-Security-Policy"));
    assert!(!report.contains('\u{1b}'));
    Ok(())
}

#[test]
fn query_limit_omissions_visible_format() -> Result<(), Box<dyn Error>> {
    let mut case = evidence_case()?;
    case.mark_incomplete("Original analysis omitted bytes after its working limit")?;
    for format in ["text", "html", "json"] {
        let output = run(
            &["query", "-", "--format", format, "--limit", "1"],
            &case.to_json()?,
        )?;
        assert_eq!(output.status.code(), Some(3), "{format}");
        let report = String::from_utf8(output.stdout)?;
        assert!(
            report.contains("Original analysis omitted bytes after its working limit"),
            "{format}"
        );
        if format == "json" {
            let value: Value = serde_json::from_str(&report)?;
            assert_eq!(value.get("omitted_matches"), Some(&json!(1)));
            assert_eq!(value.get("complete"), Some(&json!(false)));
        } else {
            assert!(report.contains("omitted=1"), "{format}");
            assert!(report.contains("collection_complete=false"), "{format}");
        }
    }
    Ok(())
}

#[test]
fn empty_query_no_relation_status() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    case.add_node("unlinked", None, Vec::new(), json!({}))?;
    let output = run(&["query", "-", "--format", "json"], &case.to_json()?)?;
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        report.pointer("/matches/0/packet_filters"),
        Some(&json!([]))
    );
    assert_eq!(report.pointer("/matches/0/relations"), Some(&json!([])));
    assert_eq!(report.pointer("/matches/0/statuses"), Some(&json!([])));
    let empty = run(
        &["query", "-", "--format", "html", "--filter", "kind=missing"],
        &case.to_json()?,
    )?;
    assert!(empty.status.success());
    assert!(String::from_utf8(empty.stdout)?.contains("No retained evidence matched"));
    Ok(())
}

#[test]
fn invalid_query_case_never_html() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let report = directory.path().join("results.html");
    for (filter, input) in [
        ("ip=invalid", evidence_case()?.to_json()?),
        ("kind=candidate", b"invalid".to_vec()),
    ] {
        let output = run(
            &[
                "query",
                "-",
                "--filter",
                filter,
                "--format",
                "html",
                "--output",
                path_arg(&report)?,
            ],
            &input,
        )?;
        assert!(!output.status.success());
        assert!(!report.exists());
    }
    fs::write(&report, b"existing evidence")?;
    let output = run(
        &[
            "query",
            "-",
            "--format",
            "html",
            "--output",
            path_arg(&report)?,
        ],
        &evidence_case()?.to_json()?,
    )?;
    assert!(!output.status.success());
    assert_eq!(fs::read(report)?, b"existing evidence");
    Ok(())
}

#[test]
fn byte_limit_keeps_omission_visible() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let candidate = case.add_node("candidate", None, Vec::new(), json!({}))?;
    let reason = "r".repeat(l2_workbench::evidence::MAX_REASON_BYTES);
    for _ in 0..16_384 {
        let witness = case.add_node("witness", None, Vec::new(), json!({}))?;
        case.add_edge(Edge {
            from: witness,
            to: candidate,
            relation: "supports".to_owned(),
            status: EvidenceStatus::Observed,
            reason: reason.clone(),
        })?;
    }
    let output = run(
        &[
            "query",
            "-",
            "--filter",
            "kind=candidate",
            "--format",
            "text",
        ],
        &case.to_json()?,
    )?;
    assert_eq!(output.status.code(), Some(3));
    let report = String::from_utf8(output.stdout)?;
    assert!(report.contains("matched=1 shown=0 omitted=1"));
    assert!(report.contains("Matched evidence did not fit"));
    assert!(!report.contains("No retained evidence matched"));
    Ok(())
}

#[test]
fn query_exports_many_matches() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    for value in 0..5_000 {
        case.add_node("row", None, Vec::new(), json!({"value":value}))?;
    }
    let output = run(
        &["query", "-", "--format", "json", "--limit", "5000"],
        &case.to_json()?,
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.get("matched_nodes"), Some(&json!(5_000)));
    assert_eq!(report.get("omitted_matches"), Some(&json!(0)));
    assert_eq!(report.get("complete"), Some(&json!(true)));
    assert_eq!(
        report
            .get("matches")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(5_000)
    );
    Ok(())
}

#[test]
fn query_byte_budget_configurable_omissions() -> Result<(), Box<dyn Error>> {
    let input = evidence_case()?.to_json()?;
    for (budget, complete, exit) in [("1", false, 3), ("8192", true, 0)] {
        let output = run(
            &[
                "query",
                "-",
                "--format",
                "json",
                "--max-report-bytes",
                budget,
            ],
            &input,
        )?;
        assert_eq!(output.status.code(), Some(exit));
        let report: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(report.get("complete"), Some(&json!(complete)));
        assert_eq!(
            report.get("omitted_matches"),
            Some(&json!(if complete { 0 } else { 2 }))
        );
    }
    for flag in ["--limit", "--max-report-bytes"] {
        let output = run(&["query", "-", flag, "0"], &input)?;
        assert_eq!(output.status.code(), Some(2));
    }
    Ok(())
}
