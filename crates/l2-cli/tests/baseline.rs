#[path = "../../../tests/fixtures/capture_paths.rs"]
mod capture_paths;
#[path = "../../../tests/fixtures/captures.rs"]
pub mod captures;

use l2_capture::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus, InterfaceId,
    TimestampResolution, TimestampSource,
};
use l2_pcap::{InterfaceConfig, MAX_EVIDENCE_OUTPUT_BYTES, PcapNgWriter};
use std::{
    error::Error,
    path::Path,
    process::{Command, Stdio},
};

fn write_inventory_limited_capture(path: &Path) -> Result<(), Box<dyn Error>> {
    let source = InterfaceId {
        section: 0,
        index: 0,
    };
    let resolution = TimestampResolution::decimal(6)?;
    let configuration = InterfaceConfig::new(65_535, resolution, 0, FcsStatus::Unknown)?;
    let mut writer = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    writer.add_interface(source, configuration)?;
    for vlan in 1..=4_097_u16 {
        let mut bytes = Vec::with_capacity(18);
        bytes.extend_from_slice(&[0xff; 6]);
        bytes.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        bytes.extend_from_slice(&0x8100_u16.to_be_bytes());
        bytes.extend_from_slice(&vlan.to_be_bytes());
        bytes.extend_from_slice(&0x0800_u16.to_be_bytes());
        let timestamp =
            CaptureTimestamp::new(u64::from(vlan), resolution, 0, TimestampSource::Unknown);
        let metadata = CaptureMetadata::new(
            source,
            u32::try_from(bytes.len())?,
            None,
            Some(timestamp),
            Direction::Unknown,
            None,
            FcsStatus::Unknown,
        );
        writer.write_frame(&CapturedFrame::new(bytes, metadata)?)?;
    }
    writer.finish()?;
    std::fs::write(path, writer.into_inner())?;
    Ok(())
}

fn write_two_source_capture(
    path: &Path,
    first_mac: [u8; 6],
    second_mac: [u8; 6],
) -> Result<(), Box<dyn Error>> {
    let resolution = TimestampResolution::decimal(6)?;
    let configuration = || InterfaceConfig::new(65_535, resolution, 0, FcsStatus::Unknown);
    let mut writer = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    for index in 0..2_u32 {
        writer.add_interface(InterfaceId { section: 0, index }, configuration()?)?;
    }
    for (index, source_mac) in [first_mac, second_mac].into_iter().enumerate() {
        let source = InterfaceId {
            section: 0,
            index: u32::try_from(index)?,
        };
        let mut bytes = vec![0xff; 6];
        bytes.extend_from_slice(&source_mac);
        bytes.extend_from_slice(&0x88b5_u16.to_be_bytes());
        let metadata = CaptureMetadata::new(
            source,
            u32::try_from(bytes.len())?,
            None,
            Some(CaptureTimestamp::new(
                u64::try_from(index + 1)?,
                resolution,
                0,
                TimestampSource::CaptureFile,
            )),
            Direction::Unknown,
            None,
            FcsStatus::Unknown,
        );
        writer.write_frame(&CapturedFrame::new(bytes, metadata)?)?;
    }
    writer.finish()?;
    std::fs::write(path, writer.into_inner())?;
    Ok(())
}

#[test]
fn baseline_create_and_compare() -> Result<(), Box<dyn Error>> {
    let fixtures = crate::capture_paths::CapturePaths::new()?;
    let directory = std::env::temp_dir().join(format!("l2solver-baseline-{}", std::process::id()));
    std::fs::create_dir(&directory)?;
    let baseline = directory.join("office.json");
    let create = || {
        Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(["baseline", "create"])
            .arg(fixtures.path("lldp.pcap"))
            .arg(&baseline)
            .output()
    };
    let created = create()?;
    assert!(created.status.success());
    assert!(
        String::from_utf8(created.stdout)?
            .contains(&baseline.display().to_string().escape_debug().to_string())
    );
    let original = std::fs::read(&baseline)?;
    assert_eq!(create()?.status.code(), Some(1));
    assert_eq!(std::fs::read(&baseline)?, original);
    let same = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["baseline", "compare"])
        .arg(&baseline)
        .arg(fixtures.path("lldp.pcap"))
        .output()?;
    assert!(same.status.success());
    let same_text = String::from_utf8(same.stdout)?;
    assert!(same_text.contains("No differences among retained observations"));
    assert!(!same_text.contains("Collection is incomplete"));
    let changed = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["baseline", "compare"])
        .arg(&baseline)
        .arg(fixtures.path("linux-stp.pcap"))
        .output()?;
    assert_eq!(changed.status.code(), Some(0));
    let text = String::from_utf8(changed.stdout)?;
    assert!(text.contains("NEW"));
    assert!(text.contains("NOT OBSERVED"));
    assert!(!text.contains("PASS"));
    assert!(!text.contains('\u{1b}'));
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[test]
fn stable_labels_survive_idb_reordering() -> Result<(), Box<dyn Error>> {
    let directory = std::env::temp_dir().join(format!(
        "l2solver-baseline-source-labels-{}",
        std::process::id()
    ));
    std::fs::create_dir(&directory)?;
    let first = directory.join("first.pcapng");
    let reordered = directory.join("reordered.pcapng");
    let baseline = directory.join("baseline.json");
    let desk = [0x02, 0, 0, 0, 0, 1];
    let conference = [0x02, 0, 0, 0, 0, 2];
    write_two_source_capture(&first, desk, conference)?;
    write_two_source_capture(&reordered, conference, desk)?;

    let create = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["baseline", "create"])
        .arg(&first)
        .arg(&baseline)
        .args(["--source", "0:0=desk-17", "--source", "0:1=conference-2"])
        .output()?;
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );

    let compare = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["baseline", "compare"])
        .arg(&baseline)
        .arg(&reordered)
        .args(["--source", "0:0=conference-2", "--source", "0:1=desk-17"])
        .output()?;
    assert!(compare.status.success());
    assert!(
        String::from_utf8(compare.stdout)?.contains("No differences among retained observations")
    );
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[test]
fn baseline_rejects_unobserved_source_mapping() -> Result<(), Box<dyn Error>> {
    let fixtures = crate::capture_paths::CapturePaths::new()?;
    let directory = std::env::temp_dir().join(format!(
        "l2solver-baseline-unobserved-source-{}",
        std::process::id()
    ));
    std::fs::create_dir(&directory)?;
    let baseline = directory.join("baseline.json");

    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["baseline", "create"])
        .arg(fixtures.path("lldp.pcap"))
        .arg(&baseline)
        .args(["--source", "0:0=desk-a", "--source", "9:9=typo"])
        .output()?;

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8(output.stderr)?.contains("unobserved interface 9:9"));
    assert!(!baseline.exists());
    assert_eq!(std::fs::read_dir(&directory)?.count(), 0);
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[test]
fn baseline_rejects_missing_source_mapping() -> Result<(), Box<dyn Error>> {
    let directory = std::env::temp_dir().join(format!(
        "l2solver-baseline-missing-source-{}",
        std::process::id()
    ));
    std::fs::create_dir(&directory)?;
    let capture = directory.join("capture.pcapng");
    let baseline = directory.join("baseline.json");
    write_two_source_capture(&capture, [0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2])?;

    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["baseline", "create"])
        .arg(&capture)
        .arg(&baseline)
        .args(["--source", "0:0=desk-a"])
        .output()?;

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8(output.stderr)?.contains("0:1 has no stable source label"));
    assert!(!baseline.exists());
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[test]
fn baseline_preserves_stp_identity_fields() -> Result<(), Box<dyn Error>> {
    let directory = std::env::temp_dir().join(format!(
        "l2solver-baseline-stp-identity-{}",
        std::process::id()
    ));
    std::fs::create_dir(&directory)?;
    let capture = directory.join("stp.pcap");
    let baseline = directory.join("stp.json");
    let mut bytes = crate::captures::LINUX_STP.to_vec();
    // Set the first root bridge's extension while leaving its priority bits unchanged
    *bytes.get_mut(24 + 16 + 23).ok_or("root bridge extension")? = 1;
    std::fs::write(&capture, bytes)?;

    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["baseline", "create"])
        .arg(&capture)
        .arg(&baseline)
        .output()?;
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&baseline)?)?;
    let facts = value
        .get("facts")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing baseline facts")?;
    assert!(facts.iter().any(|fact| {
        fact.get("kind") == Some(&serde_json::json!("stp_root"))
            && fact.get("priority") == Some(&serde_json::json!(32_768))
            && fact.get("system_id_extension") == Some(&serde_json::json!(1))
    }));
    assert!(
        !facts
            .iter()
            .any(|fact| { fact.get("priority") == Some(&serde_json::json!(32_769)) })
    );
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[test]
fn incomplete_compare_never_claims_unchanged() -> Result<(), Box<dyn Error>> {
    let fixtures = crate::capture_paths::CapturePaths::new()?;
    let directory = std::env::temp_dir().join(format!(
        "l2solver-baseline-compare-quality-{}",
        std::process::id()
    ));
    std::fs::create_dir(&directory)?;
    let baseline = directory.join("baseline.json");
    let empty_capture = directory.join("empty.pcap");
    std::fs::write(&baseline, br#"{"schema_version":2,"facts":[]}"#)?;
    std::fs::write(
        &empty_capture,
        crate::captures::LLDP.get(..24).ok_or("header")?,
    )?;

    let empty = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["baseline", "compare"])
        .arg(&baseline)
        .arg(&empty_capture)
        .output()?;
    assert_eq!(empty.status.code(), Some(3));
    assert!(String::from_utf8(empty.stdout)?.contains("Collection is incomplete"));

    let incomplete = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["baseline", "compare"])
        .arg(&baseline)
        .arg(fixtures.path("short.pcap"))
        .output()?;
    assert_eq!(incomplete.status.code(), Some(3));
    assert!(String::from_utf8(incomplete.stdout)?.contains("Collection is incomplete"));

    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[test]
fn incomplete_compare_shows_retained_differences() -> Result<(), Box<dyn Error>> {
    let directory = std::env::temp_dir().join(format!(
        "l2solver-baseline-compare-retained-{}",
        std::process::id()
    ));
    std::fs::create_dir(&directory)?;
    let baseline = directory.join("baseline.json");
    let empty_capture = directory.join("empty.pcap");
    std::fs::write(
        &baseline,
        br#"{"schema_version":2,"facts":[{"kind":"source_mac","source":"capture","mac":"retained observation"}]}"#,
    )?;
    std::fs::write(
        &empty_capture,
        crate::captures::LLDP.get(..24).ok_or("header")?,
    )?;

    let comparison = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["baseline", "compare"])
        .arg(&baseline)
        .arg(&empty_capture)
        .output()?;
    assert_eq!(comparison.status.code(), Some(3));
    let text = String::from_utf8(comparison.stdout)?;
    assert!(text.contains("NOT OBSERVED source capture MAC retained observation"));
    assert!(text.contains("Collection is incomplete"));
    assert!(!text.contains("No differences among retained observations"));

    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[cfg(unix)]
mod broken_pipe_outcomes {
    use super::*;

    #[test]
    fn incomplete_compare_keeps_status() -> Result<(), Box<dyn Error>> {
        let directory = temporary_directory("incomplete")?;
        let baseline = directory.join("baseline.json");
        let capture = directory.join("empty.pcap");
        write_large_baseline(&baseline)?;
        std::fs::write(
            &capture,
            crate::captures::LLDP.get(..24).ok_or("capture header")?,
        )?;

        let mut command = Command::new(env!("CARGO_BIN_EXE_l2solver"));
        command
            .args(["baseline", "compare"])
            .arg(&baseline)
            .arg(&capture);
        let status = run_closed(&mut command)?;

        std::fs::remove_dir_all(directory)?;
        assert_eq!(status, Some(3));
        Ok(())
    }

    #[test]
    fn changed_compare_keeps_ci_status() -> Result<(), Box<dyn Error>> {
        let fixtures = crate::capture_paths::CapturePaths::new()?;
        let directory = temporary_directory("changed")?;
        let baseline = directory.join("baseline.json");
        write_large_baseline(&baseline)?;

        let mut command = Command::new(env!("CARGO_BIN_EXE_l2solver"));
        command
            .args(["baseline", "compare"])
            .arg(&baseline)
            .arg(fixtures.path("linux-stp.pcap"))
            .arg("--fail-on-change");
        let status = run_closed(&mut command)?;

        std::fs::remove_dir_all(directory)?;
        assert_eq!(status, Some(4));
        Ok(())
    }

    fn temporary_directory(case: &str) -> Result<std::path::PathBuf, Box<dyn Error>> {
        let directory = std::env::temp_dir().join(format!(
            "l2solver-baseline-pipe-{case}-{}",
            std::process::id()
        ));
        std::fs::create_dir(&directory)?;
        Ok(directory)
    }

    fn write_large_baseline(path: &Path) -> Result<(), Box<dyn Error>> {
        let facts: Vec<_> = (0..1_024_u16)
            .map(|index| {
                serde_json::json!({
                    "kind": "source_mac",
                    "source": "capture",
                    "mac": format!("02:00:00:00:{:02x}:{:02x}", index >> 8, index & 0xff),
                })
            })
            .collect();
        std::fs::write(
            path,
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 2,
                "facts": facts,
            }))?,
        )?;
        Ok(())
    }

    fn run_closed(command: &mut Command) -> Result<Option<i32>, Box<dyn Error>> {
        command.stdout(Stdio::piped());
        let mut producer = command.spawn()?;
        // Dropping the only reader closes the output path before rendering
        drop(producer.stdout.take().ok_or("missing stdout")?);
        Ok(producer.wait()?.code())
    }
}

#[test]
fn invalid_capture_not_create_baseline() -> Result<(), Box<dyn Error>> {
    let fixtures = crate::capture_paths::CapturePaths::new()?;
    let directory =
        std::env::temp_dir().join(format!("l2solver-baseline-invalid-{}", std::process::id()));
    std::fs::create_dir(&directory)?;
    let baseline = directory.join("invalid.json");
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["baseline", "create"])
        .arg(fixtures.path("short.pcap"))
        .arg(&baseline)
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(!baseline.exists());
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[test]
fn empty_cannot_comparable_baseline() -> Result<(), Box<dyn Error>> {
    let directory =
        std::env::temp_dir().join(format!("l2solver-baseline-empty-{}", std::process::id()));
    std::fs::create_dir(&directory)?;
    let input = directory.join("empty.pcap");
    let baseline = directory.join("empty.json");
    std::fs::write(&input, crate::captures::LLDP.get(..24).ok_or("header")?)?;
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["baseline", "create"])
        .arg(input)
        .arg(&baseline)
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(!baseline.exists());
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[test]
fn incomplete_inventory_blocks_baseline() -> Result<(), Box<dyn Error>> {
    let directory = std::env::temp_dir().join(format!(
        "l2solver-baseline-inventory-limit-{}",
        std::process::id()
    ));
    std::fs::create_dir(&directory)?;
    let capture = directory.join("inventory-limit.pcapng");
    let baseline = directory.join("inventory-limit.json");
    write_inventory_limited_capture(&capture)?;

    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["baseline", "create"])
        .arg(&capture)
        .arg(&baseline)
        .output()?;
    assert!(!output.status.success());
    assert!(!baseline.exists());
    assert!(String::from_utf8(output.stderr)?.contains("incomplete capture"));
    std::fs::remove_dir_all(directory)?;
    Ok(())
}
