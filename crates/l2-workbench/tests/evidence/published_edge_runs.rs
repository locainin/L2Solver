use super::{TestResult, canonical, replace_record_value, write_published_case};
use l2_workbench::evidence::{
    Case, Edge, EvidenceStatus, MAX_EDGES, PublishedEvidenceLimits, decode_published_evidence,
};
use serde_json::{Value, json};
use std::{error::Error, io::Cursor};

const VERSION: u32 = 6;

fn add_edge(
    case: &mut Case,
    from: u64,
    to: u64,
    status: EvidenceStatus,
    reason: &str,
) -> Result<(), Box<dyn Error>> {
    case.add_edge(Edge {
        from,
        to,
        relation: "derived_from".to_owned(),
        status,
        reason: reason.to_owned(),
    })?;
    Ok(())
}

fn fixture() -> Result<Case, Box<dyn Error>> {
    let mut case = Case::new();
    for _ in 0..12 {
        case.add_node("candidate", None, Vec::new(), json!({}))?;
    }
    // Runs vary each endpoint independently and keep repeated edges in order
    for target in 2..=5 {
        add_edge(&mut case, 1, target, EvidenceStatus::Observed, "first")?;
    }
    for source in (6..=8).rev() {
        add_edge(&mut case, source, 1, EvidenceStatus::Observed, "second")?;
    }
    for offset in 0..4 {
        add_edge(
            &mut case,
            2 + offset,
            4 + offset,
            EvidenceStatus::Hypothesis,
            "third",
        )?;
    }
    for _ in 0..3 {
        add_edge(&mut case, 10, 10, EvidenceStatus::Observed, "duplicate")?;
    }
    for target in (7..=9).rev() {
        add_edge(
            &mut case,
            2,
            target,
            EvidenceStatus::Observed,
            "descending target",
        )?;
    }
    for offset in 0..3 {
        add_edge(
            &mut case,
            4 + offset,
            10 - offset,
            EvidenceStatus::Observed,
            "opposite directions",
        )?;
    }
    // Different statuses and reasons split runs even when endpoints are consecutive
    add_edge(&mut case, 1, 6, EvidenceStatus::Observed, "split")?;
    add_edge(&mut case, 1, 7, EvidenceStatus::Hypothesis, "split")?;
    add_edge(&mut case, 1, 8, EvidenceStatus::Hypothesis, "other")?;
    add_edge(&mut case, 3, 1, EvidenceStatus::Observed, "short")?;
    add_edge(&mut case, 3, 2, EvidenceStatus::Observed, "short")?;
    Ok(case)
}

fn encoded(case: &Case) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut output = Vec::new();
    write_published_case(case, &json!({"kind":"test"}), 1, &mut output)?;
    Ok(output)
}

fn decode(encoded: &[u8], limits: PublishedEvidenceLimits) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut output = Vec::new();
    decode_published_evidence(VERSION, Cursor::new(encoded), &mut output, limits)?;
    Ok(output)
}

#[test]
fn edge_runs_preserve_canonical_bytes_order_status_and_reasons() -> TestResult {
    let case = fixture()?;
    let (_, expected) = canonical(&case, &json!({"kind":"test"}), 1)?;
    let output = encoded(&case)?;
    let records = std::str::from_utf8(&output)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        records
            .first()
            .and_then(|record| record.pointer("/value/version")),
        Some(&json!(VERSION))
    );
    let runs = records
        .iter()
        .filter(|record| record.get("record") == Some(&json!("edge_run")))
        .collect::<Vec<_>>();
    assert_eq!(runs.len(), 6);
    assert_eq!(
        runs.first().and_then(|record| record.pointer("/value/2")),
        Some(&json!(0))
    );
    assert_eq!(
        runs.first().and_then(|record| record.pointer("/value/3")),
        Some(&json!(1))
    );
    assert_eq!(
        runs.get(1).and_then(|record| record.pointer("/value/2")),
        Some(&json!(-1))
    );
    assert_eq!(
        runs.get(2).and_then(|record| record.pointer("/value/2")),
        Some(&json!(1))
    );
    assert_eq!(
        runs.get(2).and_then(|record| record.pointer("/value/3")),
        Some(&json!(1))
    );
    assert_eq!(
        runs.get(3).and_then(|record| record.pointer("/value/2")),
        Some(&json!(0))
    );
    assert_eq!(
        runs.get(3).and_then(|record| record.pointer("/value/3")),
        Some(&json!(0))
    );
    assert_eq!(
        runs.get(4).and_then(|record| record.pointer("/value/3")),
        Some(&json!(-1))
    );
    assert_eq!(
        runs.get(5).and_then(|record| record.pointer("/value/2")),
        Some(&json!(1))
    );
    assert_eq!(
        runs.get(5).and_then(|record| record.pointer("/value/3")),
        Some(&json!(-1))
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| record.get("record") == Some(&json!("edge")))
            .count(),
        5
    );
    assert_eq!(
        decode(&output, PublishedEvidenceLimits::new(1_000_000, 100_000))?,
        expected
    );
    Ok(())
}

#[test]
fn edge_runs_reject_bad_steps_lengths_endpoints_and_declared_counts() -> TestResult {
    let output = encoded(&fixture()?)?;
    let limits = PublishedEvidenceLimits::new(1_000_000, 100_000);
    for (pointer, replacement, expected) in [
        ("/value/2", json!(2), "invalid evidence edge run"),
        ("/value/3", json!(-2), "invalid evidence edge run"),
        ("/value/4", json!(0), "invalid evidence edge run"),
        ("/value/4", json!(2), "invalid evidence edge run"),
        (
            "/value/4",
            json!(MAX_EDGES),
            "edge run exceeds declared edge count",
        ),
        ("/value/0", json!(0), "missing edge endpoint"),
        ("/value/1", json!(u64::MAX), "missing edge endpoint"),
        ("/value/3", json!(-1), "invalid evidence edge run endpoint"),
        ("/value/4", json!(25), "invalid evidence edge run endpoint"),
        (
            "/value/5",
            json!(999_999),
            "missing evidence dictionary reference",
        ),
        (
            "/value/7",
            json!(999_999),
            "missing evidence dictionary reference",
        ),
    ] {
        let changed = replace_record_value(&output, "edge_run", pointer, replacement)?;
        let Err(error) = decode(&changed, limits) else {
            return Err("invalid edge run was accepted".into());
        };
        assert!(
            error.to_string().contains(expected),
            "unexpected error: {error}"
        );
    }
    let short_count = replace_record_value(&output, "header", "/value/counts/edges", json!(1))?;
    let Err(error) = decode(&short_count, limits) else {
        return Err("an edge run exceeded its declared count".into());
    };
    assert!(
        error
            .to_string()
            .contains("edge run exceeds declared edge count")
    );
    let excessive = replace_record_value(
        &output,
        "header",
        "/value/counts/edges",
        json!(MAX_EDGES + 1),
    )?;
    assert!(decode(&excessive, limits).is_err());
    Ok(())
}

#[test]
fn edge_runs_obey_expanded_output_limit() -> TestResult {
    let mut case = Case::new();
    let node = case.add_node("candidate", None, Vec::new(), json!({}))?;
    for _ in 0..500 {
        add_edge(&mut case, node, node, EvidenceStatus::Observed, "repeated")?;
    }
    let output = encoded(&case)?;
    let (_, expanded) = canonical(&case, &json!({"kind":"test"}), 1)?;
    assert!(expanded.len() > output.len());
    let maximum = u64::try_from(output.len())?;
    assert!(decode(&output, PublishedEvidenceLimits::new(maximum, 100_000)).is_err());
    Ok(())
}

#[test]
fn version_five_rejects_range_records() -> TestResult {
    let output = encoded(&fixture()?)?;
    let old = replace_record_value(&output, "header", "/value/version", json!(5))?;
    let Err(error) = decode_published_evidence(
        5,
        Cursor::new(old),
        Vec::new(),
        PublishedEvidenceLimits::new(1_000_000, 100_000),
    ) else {
        return Err("version five accepted a version-six edge run".into());
    };
    assert!(error.to_string().contains("edge run requires version six"));
    Ok(())
}

#[test]
fn version_five_indexed_blob_records_remain_readable() -> TestResult {
    let mut case = Case::new();
    let bytes = b"shared legacy bytes";
    case.add_bytes_node(
        "candidate",
        bytes,
        Vec::new(),
        json!({"sha256":l2_workbench::sha256(bytes)}),
    )?;
    let scope = json!({"kind":"test"});
    let (_, expected) = canonical(&case, &scope, 1)?;
    let output = encoded(&case)?;
    let old = replace_record_value(&output, "header", "/value/version", json!(5))?;
    let mut decoded = Vec::new();
    decode_published_evidence(
        5,
        Cursor::new(old),
        &mut decoded,
        PublishedEvidenceLimits::new(1_000_000, 100_000),
    )?;
    assert_eq!(decoded, expected);
    Ok(())
}
