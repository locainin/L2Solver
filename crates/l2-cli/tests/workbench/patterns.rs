use super::support::{empty_capture, ipv4_header_frame, path_arg, run};
use l2_workbench::{
    evidence::{Case, SourceRange},
    sha256,
};
use serde_json::{Value, json};
use std::{error::Error, fs, path::PathBuf, process::Output};

fn report(output: &Output, expected_code: i32) -> Result<Value, Box<dyn Error>> {
    assert_eq!(
        output.status.code(),
        Some(expected_code),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn findings(report: &Value) -> Result<&[Value], Box<dyn Error>> {
    report
        .get("findings")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| "pattern report has no findings array".into())
}

fn smb_case(count: usize) -> Result<Case, Box<dyn Error>> {
    let mut case = Case::new();
    for _ in 0..count {
        // An incomplete generic NetBIOS frame produces one bounded timestamp finding
        case.add_bytes_node(
            "tcp_byte_run",
            &[0, 0, 0, 1],
            Vec::new(),
            json!({"start_known": true}),
        )?;
    }
    Ok(case)
}

fn clock_bundle(root: &std::path::Path) -> Result<PathBuf, Box<dyn Error>> {
    let frame = ipv4_header_frame([192, 0, 2, 1], [198, 51, 100, 2]);
    let mut bytes = empty_capture();
    for _ in 0..7 {
        // Repeated clock ticks make adjacent same-flow observations reportable
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(frame.len())?.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(frame.len())?.to_le_bytes());
        bytes.extend_from_slice(&frame);
    }
    let capture = root.join("clock.pcap");
    let bundle = root.join("bundle");
    fs::write(&capture, bytes)?;
    let output = run(
        &[
            "stream",
            path_arg(&capture)?,
            "--directory",
            path_arg(&bundle)?,
            "--page-records",
            "2",
            "--context-records",
            "2",
        ],
        b"",
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(bundle)
}

#[test]
fn pattern_commands_default_output_budgets() -> Result<(), Box<dyn Error>> {
    let input = Case::new().to_json()?;
    for command in ["behavior", "timestamps"] {
        let output = run(&[command, "-"], &input)?;
        let value = report(&output, 0)?;
        assert_eq!(
            value.get("report_limits"),
            Some(&json!({"max_findings": 4096, "max_report_bytes": 8_388_608}))
        );
        assert_eq!(value.get("omitted_findings"), Some(&json!(0)));
        assert_eq!(value.get("retained_finding_bytes"), Some(&json!(0)));
    }
    Ok(())
}

#[test]
fn pattern_commands_overflowing_budgets_output() -> Result<(), Box<dyn Error>> {
    let input = Case::new().to_json()?;
    for command in ["behavior", "timestamps"] {
        for option in ["--max-findings", "--max-report-bytes"] {
            for invalid in ["0", "-1", "184467440737095516160"] {
                let output = run(&[command, "-", option, invalid], &input)?;
                assert_eq!(output.status.code(), Some(2));
                assert_eq!(output.stdout.len(), 0);
                assert!(
                    !String::from_utf8_lossy(&output.stderr).contains("unexpected argument '--max"),
                    "the budget option must be recognized before its value is rejected"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn pattern_count_per_case_cap() -> Result<(), Box<dyn Error>> {
    let input = smb_case(4097)?.to_json()?;
    for command in ["behavior", "timestamps"] {
        let bounded = report(&run(&[command, "-"], &input)?, 3)?;
        assert_eq!(findings(&bounded)?.len(), 4096);
        assert_eq!(bounded.get("omitted_findings"), Some(&json!(1)));
        let raised = report(&run(&[command, "-", "--max-findings", "4097"], &input)?, 0)?;
        assert_eq!(findings(&raised)?.len(), 4097);
        assert_eq!(raised.get("omitted_findings"), Some(&json!(0)));
        assert_eq!(
            raised.pointer("/report_limits/max_findings"),
            Some(&json!(4097))
        );
    }
    Ok(())
}

#[test]
fn timestamp_budget_findings_category_filtering() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    for _ in 0..4097 {
        case.add_node("arp_claim_sequence", None, Vec::new(), json!({}))?;
    }
    let selected = case.add_bytes_node(
        "tcp_byte_run",
        &[0, 0, 0, 1],
        Vec::new(),
        json!({"start_known": true}),
    )?;
    let output = run(
        &["timestamps", "-", "--max-findings", "1"],
        &case.to_json()?,
    )?;
    let value = report(&output, 0)?;
    assert_eq!(findings(&value)?.len(), 1);
    assert_eq!(value.get("omitted_findings"), Some(&json!(0)));
    assert_eq!(
        value.pointer("/findings/0/node_ids"),
        Some(&json!([selected]))
    );
    Ok(())
}

#[test]
fn pattern_byte_boundaries_exact_omissions() -> Result<(), Box<dyn Error>> {
    let input = smb_case(3)?.to_json()?;
    for command in ["behavior", "timestamps"] {
        let complete = report(&run(&[command, "-"], &input)?, 0)?;
        let total_bytes = findings(&complete)?.iter().try_fold(
            0,
            |total, finding| -> Result<usize, serde_json::Error> {
                Ok(total + serde_json::to_vec(finding)?.len())
            },
        )?;
        assert_eq!(
            complete.get("retained_finding_bytes"),
            Some(&json!(total_bytes))
        );

        let tiny = report(&run(&[command, "-", "--max-report-bytes", "1"], &input)?, 3)?;
        assert_eq!(findings(&tiny)?.len(), 0);
        assert_eq!(tiny.get("omitted_findings"), Some(&json!(3)));
        assert_eq!(tiny.get("complete"), Some(&json!(false)));
        assert_eq!(tiny.get("retained_finding_bytes"), Some(&json!(0)));

        let exact = report(
            &run(
                &[command, "-", "--max-report-bytes", &total_bytes.to_string()],
                &input,
            )?,
            0,
        )?;
        assert_eq!(findings(&exact)?.len(), 3);
        assert_eq!(exact.get("omitted_findings"), Some(&json!(0)));
        assert_eq!(
            exact.get("retained_finding_bytes"),
            Some(&json!(total_bytes))
        );
        assert_eq!(
            exact.pointer("/report_limits/max_report_bytes"),
            Some(&json!(total_bytes))
        );

        let short = report(
            &run(
                &[
                    command,
                    "-",
                    "--max-report-bytes",
                    &(total_bytes - 1).to_string(),
                ],
                &input,
            )?,
            3,
        )?;
        assert_eq!(findings(&short)?.len(), 2);
        assert_eq!(short.get("omitted_findings"), Some(&json!(1)));
    }
    Ok(())
}

#[test]
fn pattern_bundle_findings_across_pages() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let bundle = clock_bundle(directory.path())?;
    for command in ["behavior", "timestamps"] {
        let complete = report(&run(&[command, path_arg(&bundle)?], b"")?, 0)?;
        assert_eq!(complete.pointer("/inventory/pages"), Some(&json!(4)));
        assert_eq!(findings(&complete)?.len(), 10);

        let bounded = report(
            &run(&[command, path_arg(&bundle)?, "--max-findings", "1"], b"")?,
            3,
        )?;
        assert_eq!(findings(&bounded)?.len(), 1);
        assert_eq!(bounded.get("omitted_findings"), Some(&json!(9)));
        assert_eq!(bounded.pointer("/inventory/pages"), Some(&json!(4)));

        let raised = report(
            &run(&[command, path_arg(&bundle)?, "--max-findings", "10"], b"")?,
            0,
        )?;
        assert_eq!(findings(&raised)?.len(), 10);
        assert_eq!(raised.get("omitted_findings"), Some(&json!(0)));
        assert!(findings(&raised)?.iter().any(|finding| {
            finding.get("page") == Some(&json!("pages/000004.json"))
                && finding
                    .get("packet_numbers")
                    .and_then(Value::as_array)
                    .is_some_and(|numbers| numbers.contains(&json!(7)))
        }));
        assert!(
            raised
                .get("limitations")
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().any(|value| {
                    value.as_str().is_some_and(|text| {
                        text.contains("bounded context window") && text.contains("unresolved")
                    })
                }))
        );
    }
    Ok(())
}

#[test]
fn pattern_largest_not_findings_vector() -> Result<(), Box<dyn Error>> {
    let input = smb_case(1)?.to_json()?;
    let maximum = usize::MAX.to_string();
    for command in ["behavior", "timestamps"] {
        let value = report(
            &run(
                &[
                    command,
                    "-",
                    "--max-findings",
                    &maximum,
                    "--max-report-bytes",
                    &maximum,
                ],
                &input,
            )?,
            0,
        )?;
        assert_eq!(findings(&value)?.len(), 1);
        assert_eq!(value.get("omitted_findings"), Some(&json!(0)));
        assert_eq!(
            value.get("report_limits"),
            Some(&json!({"max_findings": usize::MAX, "max_report_bytes": usize::MAX}))
        );
    }
    Ok(())
}

#[test]
fn pattern_byte_findings_oversized_finding() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let bytes = [0, 0, 0, 1];
    let source = case.add_source("generic.bin", "file", 4, &sha256(&bytes), None)?;
    case.add_bytes_node(
        "tcp_byte_run",
        &bytes,
        vec![SourceRange {
            source,
            packet: None,
            offset: 0,
            length: 4,
        }],
        json!({"start_known": true}),
    )?;
    let later = case.add_bytes_node(
        "tcp_byte_run",
        &bytes,
        Vec::new(),
        json!({"start_known": true}),
    )?;
    let input = case.to_json()?;
    for command in ["behavior", "timestamps"] {
        let full = report(&run(&[command, "-"], &input)?, 0)?;
        let selected = findings(&full)?;
        let first_bytes =
            serde_json::to_vec(selected.first().ok_or("first finding is missing")?)?.len();
        let last_bytes =
            serde_json::to_vec(selected.last().ok_or("last finding is missing")?)?.len();
        assert!(first_bytes > last_bytes);
        let bounded = report(
            &run(
                &[command, "-", "--max-report-bytes", &last_bytes.to_string()],
                &input,
            )?,
            3,
        )?;
        assert_eq!(findings(&bounded)?.len(), 1);
        assert_eq!(bounded.get("omitted_findings"), Some(&json!(1)));
        assert_eq!(
            bounded.pointer("/findings/0/node_ids"),
            Some(&json!([later]))
        );
        assert_eq!(
            bounded.get("retained_finding_bytes"),
            Some(&json!(last_bytes))
        );
    }
    Ok(())
}

#[test]
fn raised_pattern_source_collection_status() -> Result<(), Box<dyn Error>> {
    let mut case = smb_case(1)?;
    case.mark_incomplete("Source records were omitted")?;
    let input = case.to_json()?;
    for command in ["behavior", "timestamps"] {
        let value = report(
            &run(
                &[
                    command,
                    "-",
                    "--max-findings",
                    "8192",
                    "--max-report-bytes",
                    "16777216",
                ],
                &input,
            )?,
            3,
        )?;
        assert_eq!(value.get("complete"), Some(&json!(false)));
        assert_eq!(
            value.pointer("/inventory/collection_complete"),
            Some(&json!(false))
        );
        assert_eq!(value.get("omitted_findings"), Some(&json!(0)));
        assert!(
            value
                .get("limitations")
                .and_then(Value::as_array)
                .is_some_and(|values| { values.contains(&json!("Source records were omitted")) })
        );
    }
    Ok(())
}
