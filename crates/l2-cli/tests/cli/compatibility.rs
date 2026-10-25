use l2_cli::arguments::{Command, IndexedCommand, LiveLimit, WorkbenchCommand, parse};
use std::{ffi::OsString, path::PathBuf, time::Duration};

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[test]
fn hidden_capture_commands_remain_parseable() -> Result<(), Box<dyn std::error::Error>> {
    for (words, expected) in [
        (
            vec!["inspect", "capture.pcap"],
            Command::Inspect(PathBuf::from("capture.pcap")),
        ),
        (
            vec!["observe", "capture.pcap"],
            Command::Observe(PathBuf::from("capture.pcap")),
        ),
        (
            vec!["json", "capture.pcap"],
            Command::Json(PathBuf::from("capture.pcap")),
        ),
    ] {
        assert_eq!(parse(&args(&words))?, expected);
    }
    Ok(())
}

#[test]
fn survey_alias_uses_assessment_model() -> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        parse(&args(&["survey", "capture.pcap"]))?,
        Command::Assess(_)
    ));
    Ok(())
}

#[test]
fn direct_path_no_longer_ambiguous() {
    assert!(parse(&args(&["capture.pcap"])).is_err());
}

#[test]
fn hidden_live_alias_accepts_duration() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        parse(&args(&["listen", "eth0", "1m"]))?,
        Command::Listen {
            interface: String::from("eth0"),
            limit: LiveLimit::Duration(Duration::from_mins(1)),
        }
    );
    Ok(())
}

#[test]
fn indexed_flow_ordered_cohort_budgets() -> Result<(), Box<dyn std::error::Error>> {
    let single = parse(&args(&["workbench", "indexed", "index", "flow", "17"]))?;
    let Command::Workbench(WorkbenchCommand::Indexed {
        operation: IndexedCommand::Flow(single),
        ..
    }) = single
    else {
        return Err("single indexed flow command was not retained".into());
    };
    assert_eq!(single.flow, [17]);
    assert_eq!(
        single.limits(),
        l2_workbench::reconstruction::Limits::default()
    );

    let cohort = parse(&args(&[
        "workbench",
        "indexed",
        "index",
        "flow",
        "29",
        "17",
        "--max-frames",
        "3",
        "--max-bytes",
        "8192",
    ]))?;
    let Command::Workbench(WorkbenchCommand::Indexed {
        operation: IndexedCommand::Flow(cohort),
        ..
    }) = cohort
    else {
        return Err("multi-flow indexed command was not retained".into());
    };
    assert_eq!(cohort.flow, [29, 17]);
    assert_eq!(cohort.limits().frames, 3);
    assert_eq!(cohort.limits().bytes, 8192);
    Ok(())
}

#[test]
fn accepts_reconstruction_without_changing_output() -> Result<(), Box<dyn std::error::Error>> {
    let command = parse(&args(&[
        "workbench",
        "build",
        "capture.pcap",
        "--output",
        "case.json",
        "--max-frames",
        "7",
        "--max-bytes",
        "8192",
        "--max-units",
        "13",
        "--max-sessions",
        "3",
        "--max-datagrams",
        "5",
        "--max-range-bytes",
        "4096",
        "--max-range-observations",
        "17",
        "--max-range-retained-bytes",
        "1024",
    ]))?;
    let Command::Workbench(WorkbenchCommand::Build {
        capture,
        resources,
        output,
    }) = command
    else {
        return Err("build command was not retained".into());
    };
    assert_eq!(capture, PathBuf::from("capture.pcap"));
    assert_eq!(output, Some(PathBuf::from("case.json")));
    assert_eq!(
        resources.limits(),
        l2_workbench::reconstruction::Limits {
            frames: 7,
            bytes: 8192,
            units: 13,
            sessions: 3,
            datagrams: 5,
            range_bytes: 4096,
            range_observations: 17,
            range_retained_bytes: 1024,
        }
    );
    Ok(())
}
