use std::process::Command;

#[test]
fn short_help_developer_namespace_hidden() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("-h")
        .output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(!text.contains("l2solver dev --help"));
    assert!(!text.contains("Internal diagnostics"));
    Ok(())
}

#[test]
fn long_help_points_developer_namespace() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("--help")
        .output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("l2solver dev --help"));
    assert!(!text.contains("dev  Internal diagnostics"));
    assert!(text.contains("Exit status:"));
    assert!(text.contains("3  Assessment, collection, export, or workbench result is incomplete"));
    assert!(text.contains(
        "4  Active identity findings; findings with --fail-on-findings/--ci; or baseline changes with --fail-on-change"
    ));
    assert!(!text.contains("3  Assessment incomplete"));
    assert!(!text.contains("4  Confirmed findings when --fail-on-findings is selected"));
    Ok(())
}

#[test]
fn subcommand_help_is_scoped() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["capture", "--help"])
        .output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("inspect"));
    assert!(text.contains("observe"));
    assert!(text.contains("dump"));
    assert!(!text.contains("baseline create"));
    Ok(())
}

#[test]
fn root_inspect_is_listed() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("--help")
        .output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(
        text.lines()
            .any(|line| line.trim_start().starts_with("inspect ")),
        "root help does not list inspect:\n{text}"
    );
    Ok(())
}

#[test]
fn report_defaults_text() -> Result<(), Box<dyn std::error::Error>> {
    for args in [
        &["workbench", "review", "--help"][..],
        &["workbench", "correlate", "--help"][..],
        &["workbench", "journal", "review", "--help"][..],
        &["workbench", "carrier-results", "list", "--help"][..],
        &["workbench", "carrier-results", "show", "--help"][..],
        &["workbench", "carrier-results", "sources", "--help"][..],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(args)
            .output()?;
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout)?;
        assert!(text.contains("[default: text]"), "{args:?}: {text}");
    }
    let carrier = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["workbench", "carrier-results", "--help"])
        .output()?;
    assert!(carrier.status.success());
    let carrier = String::from_utf8(carrier.stdout)?;
    assert!(carrier.contains("report pages or exported bytes"));
    assert!(!carrier.contains("JSON pages"));

    let review = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["workbench", "review", "--help"])
        .output()?;
    assert!(review.status.success());
    let review = String::from_utf8(review.stdout)?;
    assert!(review.contains("Choose text, JSON, or HTML report output"));
    Ok(())
}

#[test]
fn directory_commands_explain_formats() -> Result<(), Box<dyn std::error::Error>> {
    for args in [
        &["workbench", "index", "--help"][..],
        &["workbench", "stream", "--help"][..],
        &["workbench", "carrier-results", "discover", "--help"][..],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(args)
            .output()?;
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout)?;
        assert!(text.contains("[default: text]"), "{args:?}: {text}");
        assert!(
            text.contains("text summary") && text.contains("JSON receipt"),
            "{args:?}: {text}"
        );
    }
    Ok(())
}

#[test]
fn assess_help_is_clear() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["assess", "--help"])
        .output()?;
    assert!(output.status.success());
    assert_eq!(output.stderr.len(), 0);
    let text = String::from_utf8(output.stdout)?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for detail in [
        "offline capture",
        "--interface",
        "mutually exclusive",
        "--duration",
        "--packets",
        "1s to 5m",
        "1 to 10000",
        "--features live",
        "standard output",
        "--format",
        "text, JSON, or HTML",
        "--output",
    ] {
        assert!(text.contains(detail), "missing {detail}: {text}");
    }
    Ok(())
}

#[test]
fn observe_help_is_specific() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["capture", "observe", "--help"])
        .output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for detail in ["STP", "advertisements", "root changes", "capture time"] {
        assert!(text.contains(detail), "missing {detail}: {text}");
    }
    Ok(())
}

#[test]
fn help_explains_incomplete_exit_status() -> Result<(), Box<dyn std::error::Error>> {
    for help in ["-h", "--help"] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(["workbench", "export", help])
            .output()?;
        assert!(output.status.success());
        assert_eq!(output.stderr.len(), 0);
        let text = String::from_utf8(output.stdout)?
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains("binary stdout"));
        assert!(text.contains("--output"));
        assert!(text.contains("new file"));
        assert!(text.contains("incomplete case"));
        assert!(text.contains("exit status 3"));
        assert!(text.contains("stderr"));
    }
    Ok(())
}

#[test]
fn extract_all_help_describes_retained_case_artifacts() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["workbench", "extract-all", "--help"])
        .output()?;
    assert!(output.status.success());
    assert_eq!(output.stderr.len(), 0);
    let text = String::from_utf8(output.stdout)?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        text.contains("already retained"),
        "missing retention scope: {text}"
    );
    assert!(text.contains("Materialize recovered artifacts"), "{text}");
    assert!(text.contains("Case"), "missing Case context: {text}");
    Ok(())
}

#[test]
fn help_reconstruction_defaults_complete_routes() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["workbench", "build", "--help"])
        .output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    for option in [
        "--max-frames",
        "--max-bytes",
        "--max-units",
        "--max-sessions",
        "--max-datagrams",
        "--max-range-bytes",
        "--max-range-observations",
        "--max-range-retained-bytes",
    ] {
        assert!(text.contains(option), "missing {option}");
    }
    assert!(text.contains("16777216"));
    assert!(text.contains("65536"));
    assert!(text.contains("16384"));
    assert!(text.contains("workbench stream"));
    assert!(text.contains("workbench index"));
    Ok(())
}

#[test]
fn expand_help_explains_zip_budget() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["workbench", "expand", "--help"])
        .output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(text.contains("--max-zip-work-bytes"));
    assert!(
        text.contains("charged before extraction across all ZIPs, including failed validation")
    );
    assert!(text.contains("[default: 67108864]"));
    Ok(())
}

#[test]
fn tshark_journal_count_budget_precisely() -> Result<(), Box<dyn std::error::Error>> {
    let tshark = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["workbench", "tshark", "--help"])
        .output()?;
    assert!(tshark.status.success());
    let tshark = String::from_utf8(tshark.stdout)?;
    assert!(tshark.contains("source-frame-count output"), "{tshark}");

    let journal = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["workbench", "journal", "import-tshark", "--help"])
        .output()?;
    assert!(journal.status.success());
    let journal = String::from_utf8(journal.stdout)?;
    for text in ["L2Solver", "TShark", "receipt", "source hash and length"] {
        assert!(journal.contains(text), "missing {text}: {journal}");
    }
    assert!(!journal.contains("TShark JSON report"), "{journal}");
    Ok(())
}
