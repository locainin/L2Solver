use l2_capture::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus, InterfaceId,
    TimestampResolution, TimestampSource,
};
use l2_pcap::{
    CollectionGoal, CollectionReport, CollectionStopReason, InterfaceConfig, PcapNgWriter,
};
use serde_json::{Value, json};
use std::{error::Error, path::Path, process::Command};

const ARP: &[u8] = &[
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1, 0x08, 0x06, // Ethernet
    0, 1, 0x08, 0, 6, 4, 0, 1, 0x02, 0, 0, 0, 0, 1, 192, 0, 2, 1, // ARP sender
    0, 0, 0, 0, 0, 0, 192, 0, 2, 2, // ARP target
];

fn fixture(path: &Path, reported: bool) -> Result<(), Box<dyn Error>> {
    let mut writer = if reported {
        // The section claims zero received packets despite containing one frame
        PcapNgWriter::new_with_collection_report(
            Vec::new(),
            1_048_576,
            CollectionReport::new(
                CollectionStopReason::Deadline,
                CollectionGoal::Duration,
                0,
                0,
                0,
                true,
            ),
        )?
    } else {
        PcapNgWriter::new(Vec::new(), 1_048_576)?
    };
    let interface = InterfaceId {
        section: 0,
        index: 0,
    };
    let time = CaptureTimestamp::new(
        1_000_000,
        TimestampResolution::MICROSECOND,
        0,
        TimestampSource::Unknown,
    );
    let frame = CapturedFrame::new(
        ARP.to_vec(),
        CaptureMetadata::new(
            interface,
            u32::try_from(ARP.len())?,
            None,
            Some(time),
            Direction::Unknown,
            None,
            FcsStatus::Unknown,
        ),
    )?;
    let config = InterfaceConfig::new(
        65_535,
        TimestampResolution::MICROSECOND,
        0,
        FcsStatus::Unknown,
    )?;
    writer.add_interface_and_write_frame(interface, config, &frame)?;
    writer.finish()?;
    std::fs::write(path, writer.into_inner())?;
    Ok(())
}

fn run(path: &Path, args: &[&str]) -> Result<std::process::Output, Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(args)
        .arg(path)
        .output()?;
    assert!(
        output.status.success(),
        "{}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

fn check_authority(reported: bool, authority: &str) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join(format!("{authority}.pcapng"));
    fixture(&path, reported)?;
    let expected_hash = if reported {
        "a418b12679580c6091c2b22d8b05b7477c977826d79974add9bd1e732205d0b3"
    } else {
        "f85df08c94e0ac11965d6415db77ff406c727be05f734d7b00b7b5c63b401bf4"
    };
    assert_eq!(l2_workbench::sha256(&std::fs::read(&path)?), expected_hash);

    check_capture_reports(&path, reported, authority)?;
    check_assessment(&path, authority)?;
    check_workbench(&path, directory.path(), authority)
}

fn check_capture_reports(
    path: &Path,
    reported: bool,
    authority: &str,
) -> Result<(), Box<dyn Error>> {
    let inspection = String::from_utf8(run(path, &["inspect"])?.stdout)?;
    assert!(inspection.contains("frames=1"), "{inspection}");
    assert!(
        inspection.contains("acquisition_quality=unverified"),
        "{inspection}"
    );
    assert!(
        inspection.contains(&format!("authority={authority}")),
        "{inspection}"
    );

    let output = run(path, &["json"])?;
    let records = std::str::from_utf8(&output.stdout)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let summary = records
        .iter()
        .find(|value| value.get("record_type") == Some(&json!("source_collection")))
        .ok_or("missing source collection summary")?;
    assert_eq!(summary.get("authority"), Some(&json!(authority)));
    assert_eq!(
        summary.get("acquisition_quality"),
        Some(&json!("unverified"))
    );
    assert_eq!(
        summary.pointer("/source_collection/reported_sections"),
        Some(&json!(u8::from(reported)))
    );

    Ok(())
}

fn check_assessment(path: &Path, authority: &str) -> Result<(), Box<dyn Error>> {
    let assessment = String::from_utf8(run(path, &["assess", "-vv"])?.stdout)?;
    assert!(assessment.contains("Analysis     COMPLETE"), "{assessment}");
    assert!(
        assessment.contains("Acquisition  UNVERIFIED"),
        "{assessment}"
    );
    assert!(
        !assessment.contains("Capture      COMPLETE"),
        "{assessment}"
    );
    assert!(
        !assessment.contains("PASS — no parser, truncation, loss"),
        "{assessment}"
    );

    let result = run(path, &["assess", "--format", "json"])?;
    let result: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(result.get("analysis_complete"), Some(&json!(true)));
    assert_eq!(
        result.pointer("/acquisition_quality/status"),
        Some(&json!("unverified"))
    );
    assert_eq!(
        result.pointer("/acquisition_quality/authority"),
        Some(&json!(authority))
    );

    Ok(())
}

fn check_workbench(path: &Path, directory: &Path, authority: &str) -> Result<(), Box<dyn Error>> {
    let output = run(path, &["workbench", "build"])?;
    let case = l2_workbench::evidence::Case::from_json(&output.stdout)?;
    assert!(case.collection_complete());
    let summary = case
        .nodes()
        .iter()
        .find(|node| node.kind == "capture_collection_summary")
        .ok_or("missing capture collection node")?;
    assert_eq!(
        summary.details.pointer("/summary/authority"),
        Some(&json!(authority))
    );
    assert!(
        case.limitations()
            .iter()
            .any(|value| value.contains("acquisition quality is unverified"))
    );

    let bundle = directory.join("bundle");
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["workbench", "stream"])
        .arg(path)
        .arg("--directory")
        .arg(&bundle)
        .args(["--format", "json"])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(receipt.get("analysis_complete"), Some(&json!(true)));
    assert_eq!(
        receipt.pointer("/acquisition_quality/status"),
        Some(&json!("unverified"))
    );
    assert_eq!(
        receipt.pointer("/acquisition_quality/authority"),
        Some(&json!(authority))
    );
    Ok(())
}

#[test]
fn absent_report_unverified() -> Result<(), Box<dyn Error>> {
    check_authority(false, "absent")
}

#[test]
fn forged_report_unverified() -> Result<(), Box<dyn Error>> {
    check_authority(true, "source_declared")
}

fn check_baseline_authority(reported: bool, authority: &str) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.pcapng");
    let baseline = directory.path().join("baseline.json");
    fixture(&path, reported)?;
    let expected =
        format!("analysis_complete=true acquisition_quality=unverified authority={authority}");
    let created = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["baseline", "create"])
        .arg(&path)
        .arg(&baseline)
        .output()?;
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let text = String::from_utf8(created.stdout)?;
    assert!(text.contains(&expected), "{text}");

    let compared = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["baseline", "compare"])
        .arg(&baseline)
        .arg(&path)
        .output()?;
    assert!(
        compared.status.success(),
        "{}",
        String::from_utf8_lossy(&compared.stderr)
    );
    let text = String::from_utf8(compared.stdout)?;
    assert!(text.contains(&expected), "{text}");
    assert!(
        text.contains("Baseline acquisition quality is unverified"),
        "{text}"
    );
    Ok(())
}

#[test]
fn absent_baseline_acquisition_unverified() -> Result<(), Box<dyn Error>> {
    check_baseline_authority(false, "absent")
}

#[test]
fn forged_baseline_acquisition_unverified() -> Result<(), Box<dyn Error>> {
    check_baseline_authority(true, "source_declared")
}
