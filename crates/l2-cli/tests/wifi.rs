#[path = "../../../tests/fixtures/capture_paths.rs"]
mod capture_paths;
#[path = "../../../tests/fixtures/captures.rs"]
pub mod captures;

use l2_capture::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus, InterfaceId, LinkType,
    TimestampResolution, TimestampSource,
};
use l2_pcap::{InterfaceConfig, PcapNgWriter};
use std::{
    error::Error,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

const BSSID: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
static CAPTURE_ID: AtomicU64 = AtomicU64::new(0);

fn beacon_with_bssid(bssid: [u8; 6]) -> Vec<u8> {
    beacon_named_on_channel(bssid, b"Test", 6)
}

fn radiotap(bytes: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(8 + bytes.len());
    // Version 0, no present words, and an eight-byte radiotap header
    frame.extend_from_slice(&[0, 0, 8, 0, 0, 0, 0, 0]);
    frame.extend_from_slice(bytes);
    frame
}

fn beacon_named_on_channel(bssid: [u8; 6], ssid: &[u8], channel: u8) -> Vec<u8> {
    let ssid_length = u8::try_from(ssid.len()).ok().unwrap_or(0);
    let mut frame = Vec::from(0x0080_u16.to_le_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&0_u64.to_le_bytes());
    frame.extend_from_slice(&100_u16.to_le_bytes());
    frame.extend_from_slice(&0_u16.to_le_bytes());
    frame.extend_from_slice(&[0, ssid_length]);
    frame.extend_from_slice(ssid);
    frame.extend_from_slice(&[3, 1, channel]);
    frame
}

fn write_capture() -> Result<std::path::PathBuf, Box<dyn Error>> {
    write_capture_with_beacons(1)
}

fn write_radiotap_capture() -> Result<PathBuf, Box<dyn Error>> {
    let interface = InterfaceId {
        section: 0,
        index: 0,
    };
    let mut writer = PcapNgWriter::new(Vec::new(), 1_048_576)?;
    writer.add_interface(
        interface,
        InterfaceConfig::new_with_link_type(
            LinkType::Ieee80211Radiotap,
            4_096,
            TimestampResolution::MICROSECOND,
            0,
            FcsStatus::Unknown,
        )?,
    )?;
    let beacon = radiotap(&beacon_with_bssid(BSSID));
    let metadata = CaptureMetadata::new(
        interface,
        u32::try_from(beacon.len())?,
        None,
        Some(CaptureTimestamp::new(
            1,
            TimestampResolution::MICROSECOND,
            0,
            TimestampSource::CaptureFile,
        )),
        Direction::Unknown,
        None,
        FcsStatus::Unknown,
    )
    .with_link_type(LinkType::Ieee80211Radiotap);
    writer.write_frame(&CapturedFrame::new(beacon, metadata)?)?;
    save(writer)
}

fn write_capture_with_beacons(count: usize) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let interface = InterfaceId {
        section: 0,
        index: 0,
    };
    let mut writer = writer(FcsStatus::Unknown)?;
    for sequence in 1..=count {
        let sequence = u16::try_from(sequence)?;
        let bssid = [
            BSSID[0],
            BSSID[1],
            BSSID[2],
            BSSID[3],
            u8::try_from(sequence >> 8)?,
            u8::try_from(sequence & 0xff)?,
        ];
        let bytes = beacon_with_bssid(bssid);
        let metadata = CaptureMetadata::new(
            interface,
            u32::try_from(bytes.len())?,
            None,
            Some(CaptureTimestamp::new(
                u64::from(sequence),
                TimestampResolution::MICROSECOND,
                0,
                TimestampSource::CaptureFile,
            )),
            Direction::Unknown,
            None,
            FcsStatus::Unknown,
        )
        .with_link_type(LinkType::Ieee80211);
        writer.write_frame(&CapturedFrame::new(bytes, metadata)?)?;
    }
    save(writer)
}

fn writer(fcs: FcsStatus) -> Result<PcapNgWriter<Vec<u8>>, Box<dyn Error>> {
    let interface = InterfaceId {
        section: 0,
        index: 0,
    };
    let mut writer = PcapNgWriter::new(Vec::new(), 1_048_576)?;
    writer.add_interface(
        interface,
        InterfaceConfig::new_with_link_type(
            LinkType::Ieee80211,
            4_096,
            TimestampResolution::MICROSECOND,
            0,
            fcs,
        )?,
    )?;
    Ok(writer)
}

fn write_frame(
    writer: &mut PcapNgWriter<Vec<u8>>,
    bytes: Vec<u8>,
    original_len: u32,
    fcs: FcsStatus,
) -> Result<(), Box<dyn Error>> {
    let interface = InterfaceId {
        section: 0,
        index: 0,
    };
    let metadata = CaptureMetadata::new(
        interface,
        original_len,
        None,
        Some(CaptureTimestamp::new(
            1,
            TimestampResolution::MICROSECOND,
            0,
            TimestampSource::CaptureFile,
        )),
        Direction::Unknown,
        None,
        fcs,
    )
    .with_link_type(LinkType::Ieee80211);
    writer.write_frame(&CapturedFrame::new(bytes, metadata)?)?;
    Ok(())
}

fn save(mut writer: PcapNgWriter<Vec<u8>>) -> Result<PathBuf, Box<dyn Error>> {
    writer.finish()?;
    let bytes = writer.into_inner();
    for _ in 0..1_024 {
        let id = CAPTURE_ID.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("l2solver-wifi-cli-{}-{id}", std::process::id()));
        match std::fs::create_dir(&directory) {
            Ok(()) => {
                let path = directory.join("wireless.pcapng");
                std::fs::write(&path, &bytes)?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err("could not allocate a unique wireless test directory".into())
}

#[cfg(unix)]
#[test]
fn wifi_command_closed_output_pipe() -> Result<(), Box<dyn Error>> {
    let path = write_capture_with_beacons(4_096)?;
    let mut producer = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("wifi")
        .arg("assess")
        .arg(&path)
        .stdout(Stdio::piped())
        .spawn()?;
    let producer_output = producer.stdout.take().ok_or("missing producer stdout")?;
    let consumer = Command::new("head")
        .args(["-n", "1"])
        .stdin(producer_output)
        .stdout(Stdio::null())
        .spawn()?
        .wait()?;

    assert!(consumer.success());
    assert!(
        producer.wait()?.success(),
        "wifi treated BrokenPipe as failure"
    );
    std::fs::remove_dir_all(path.parent().ok_or("capture has no parent")?)?;
    Ok(())
}

#[cfg(unix)]
mod broken_pipe_outcomes {
    use super::*;

    #[test]
    fn incomplete_assessment_keeps_status() -> Result<(), Box<dyn Error>> {
        let fixtures = crate::capture_paths::CapturePaths::new()?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_l2solver"));
        command
            .args(["wifi", "assess"])
            .arg(fixtures.path("lldp.pcap"));

        assert_eq!(run_closed(&mut command)?, Some(3));
        Ok(())
    }

    #[test]
    fn ci_finding_keeps_status() -> Result<(), Box<dyn Error>> {
        let path = write_capture()?;
        let parent = path.parent().ok_or("capture has no parent")?;
        let policy = parent.join("wireless-policy.json");
        std::fs::write(
            &policy,
            r#"{"networks":[],"unlisted_ssids_forbidden":true}"#,
        )?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_l2solver"));
        command
            .args(["wifi", "assess"])
            .arg(&path)
            .arg("--policy")
            .arg(&policy)
            .arg("--ci");

        let status = run_closed(&mut command)?;
        std::fs::remove_dir_all(parent)?;
        assert_eq!(status, Some(4));
        Ok(())
    }

    fn run_closed(command: &mut Command) -> Result<Option<i32>, Box<dyn Error>> {
        command.stdout(Stdio::piped());
        let mut producer = command.spawn()?;
        // Closing the only reader forces presentation to encounter BrokenPipe
        drop(producer.stdout.take().ok_or("missing stdout")?);
        Ok(producer.wait()?.code())
    }
}

#[test]
fn wifi_command_surveys_typed_capture() -> Result<(), Box<dyn Error>> {
    let path = write_capture()?;

    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("wifi")
        .arg("assess")
        .arg(&path)
        .output()?;

    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    for heading in [
        "L2Solver wireless assessment",
        "Findings",
        "Attack surface",
        "Not tested",
    ] {
        assert!(text.contains(heading), "missing {heading}");
    }
    assert!(text.contains("Access points 1"));
    assert!(text.contains("Test"));
    assert!(text.contains("Open"));
    assert!(text.contains("WIFI-ENC-OPEN"));
    assert!(!text.contains("ap="));
    std::fs::remove_dir_all(path.parent().ok_or("capture has no parent")?)?;
    Ok(())
}

#[test]
fn wifi_command_routes_radiotap_metadata() -> Result<(), Box<dyn Error>> {
    let path = write_radiotap_capture()?;
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("wifi")
        .arg("assess")
        .arg(&path)
        .arg("-v")
        .output()?;

    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("access_points=1"));
    assert!(text.contains("ssid=Test"));
    std::fs::remove_dir_all(path.parent().ok_or("capture has no parent")?)?;
    Ok(())
}

#[test]
fn wifi_policy_ci_exit_mode() -> Result<(), Box<dyn Error>> {
    let path = write_capture()?;
    let parent = path.parent().ok_or("capture has no parent")?;
    let policy = parent.join("wireless-policy.json");
    std::fs::write(
        &policy,
        r#"{"networks":[],"unlisted_ssids_forbidden":true}"#,
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("wifi")
        .arg("assess")
        .arg(&path)
        .arg("--policy")
        .arg(&policy)
        .output()?;

    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("WIFI-SSID-POLICY-001"));
    assert!(text.contains("HIGH"));
    assert!(text.contains("Verdict    Fail"));

    let html = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["wifi", "assess"])
        .arg(&path)
        .arg("--policy")
        .arg(&policy)
        .arg("--format")
        .arg("html")
        .output()?;
    assert!(html.status.success());
    let html_text = String::from_utf8(html.stdout)?;
    assert!(html_text.contains("Verdict    Fail"));

    let ci = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["wifi", "assess"])
        .arg(&path)
        .arg("--policy")
        .arg(&policy)
        .arg("--ci")
        .output()?;
    assert_eq!(ci.status.code(), Some(4));
    std::fs::remove_dir_all(parent)?;
    Ok(())
}

#[test]
fn wifi_policy_unknown_nested_fields() -> Result<(), Box<dyn Error>> {
    let path = write_capture()?;
    let parent = path.parent().ok_or("capture has no parent")?;
    let policy = parent.join("wireless-policy-unknown-field.json");
    std::fs::write(
        &policy,
        r#"{
            "networks": [{
                "ssid": [84, 101, 115, 116],
                "allowed_bssids": [],
                "security_modes": [],
                "pmf": "Optional",
                "wps_allowed": false,
                "allowed_channels": [],
                "wps_alowed": true
            }],
            "unlisted_ssids_forbidden": false
        }"#,
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["wifi", "assess"])
        .arg(&path)
        .arg("--policy")
        .arg(&policy)
        .output()?;

    std::fs::remove_dir_all(parent)?;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8(output.stderr)?.contains("unknown field"));
    Ok(())
}

#[test]
fn wifi_text_retains_advertisement_drift() -> Result<(), Box<dyn Error>> {
    let fixtures = crate::capture_paths::CapturePaths::new()?;
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["wifi", "assess"])
        .arg(fixtures.path("wifi-drift-radiotap.pcap"))
        .arg("-v")
        .output()?;

    assert_eq!(output.status.code(), Some(3));
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("ssid_conflict=CorpWiFi-Lab"));
    assert!(text.contains("ssid_inconsistent=true"));
    assert!(text.contains("channel_changed=true"));
    assert!(text.contains("WIFI-IDENTITY-DRIFT"));
    assert!(text.contains("WIFI-CHANNEL-DRIFT"));
    Ok(())
}

#[test]
fn wifi_command_ethernet_input_honestly() -> Result<(), Box<dyn Error>> {
    let fixtures = crate::capture_paths::CapturePaths::new()?;
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["wifi", "assess"])
        .arg(fixtures.path("lldp.pcap"))
        .arg("-vv")
        .output()?;

    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8(output.stdout)?.contains("unsupported_link=1"));
    Ok(())
}

mod evidence_quality {
    use super::*;

    #[test]
    fn declared_fcs_not_remove_bytes() -> Result<(), Box<dyn Error>> {
        let fcs = FcsStatus::present(4)?;
        let mut writer = writer(fcs)?;
        let frame = beacon_with_bssid(BSSID);
        write_frame(&mut writer, frame.clone(), u32::try_from(frame.len())?, fcs)?;
        let path = save(writer)?;

        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg("wifi")
            .arg("assess")
            .arg(&path)
            .arg("-v")
            .output()?;

        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout)?.contains("ssid=Test"));
        std::fs::remove_dir_all(path.parent().ok_or("capture has no parent")?)?;
        Ok(())
    }

    #[test]
    fn truncated_capture_is_incomplete() -> Result<(), Box<dyn Error>> {
        let mut writer = writer(FcsStatus::Unknown)?;
        let frame = beacon_with_bssid(BSSID);
        let original_len = u32::try_from(frame.len())?
            .checked_add(8)
            .ok_or("length overflow")?;
        write_frame(&mut writer, frame, original_len, FcsStatus::Unknown)?;
        let path = save(writer)?;
        let parent = path.parent().ok_or("capture has no parent")?;
        let policy = parent.join("wireless-policy.json");
        std::fs::write(
            &policy,
            r#"{"networks":[{"ssid":[84,101,115,116],"allowed_bssids":[],"security_modes":["Wpa3Personal"],"pmf":"Optional","wps_allowed":false,"allowed_channels":[]}],"unlisted_ssids_forbidden":false}"#,
        )?;

        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg("wifi")
            .arg("assess")
            .arg(&path)
            .arg("--policy")
            .arg(&policy)
            .arg("-v")
            .output()?;

        assert_eq!(output.status.code(), Some(3));
        let text = String::from_utf8(output.stdout)?;
        assert!(text.contains("security=Unknown"));
        assert!(text.contains("WIFI-SEC-UNKNOWN-001"));
        assert!(text.contains("Verdict    Potential"));
        assert!(text.contains("coverage=WIFI-PASSIVE-SURVEY status=Incomplete"));
        assert!(!text.contains("WIFI-ENC-OPEN"));
        assert!(!text.contains("WIFI-ENC-WEP"));
        std::fs::remove_dir_all(parent)?;
        Ok(())
    }

    #[test]
    fn empty_capture_is_not_tested() -> Result<(), Box<dyn Error>> {
        let path = save(writer(FcsStatus::Unknown)?)?;

        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg("wifi")
            .arg("assess")
            .arg(&path)
            .arg("-v")
            .output()?;

        assert_eq!(output.status.code(), Some(3));
        assert!(
            String::from_utf8(output.stdout)?
                .contains("coverage=WIFI-PASSIVE-SURVEY status=NotTested")
        );
        std::fs::remove_dir_all(path.parent().ok_or("capture has no parent")?)?;
        Ok(())
    }

    #[test]
    fn control_only_capture_not_tested() -> Result<(), Box<dyn Error>> {
        let mut writer = writer(FcsStatus::Unknown)?;
        let ack = vec![0xd4, 0x00, 0, 0, 2, 0, 0, 0, 0, 1];
        write_frame(
            &mut writer,
            ack.clone(),
            u32::try_from(ack.len())?,
            FcsStatus::Unknown,
        )?;
        let path = save(writer)?;

        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg("wifi")
            .arg("assess")
            .arg(&path)
            .arg("-v")
            .output()?;

        assert_eq!(output.status.code(), Some(3));
        assert!(
            String::from_utf8(output.stdout)?
                .contains("coverage=WIFI-PASSIVE-SURVEY status=NotTested")
        );
        std::fs::remove_dir_all(path.parent().ok_or("capture has no parent")?)?;
        Ok(())
    }

    #[test]
    fn protected_only_capture_is_incomplete() -> Result<(), Box<dyn Error>> {
        let mut writer = writer(FcsStatus::Unknown)?;
        let mut frame = beacon_with_bssid(BSSID);
        frame
            .get_mut(..2)
            .ok_or("beacon lacks frame control")?
            .copy_from_slice(&0x4080_u16.to_le_bytes());
        write_frame(
            &mut writer,
            frame.clone(),
            u32::try_from(frame.len())?,
            FcsStatus::Unknown,
        )?;
        let path = save(writer)?;

        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg("wifi")
            .arg("assess")
            .arg(&path)
            .arg("-v")
            .output()?;

        assert_eq!(output.status.code(), Some(3));
        let text = String::from_utf8(output.stdout)?;
        assert!(text.contains("access_points=1"));
        assert!(text.contains("coverage=WIFI-PASSIVE-SURVEY status=Incomplete"));
        std::fs::remove_dir_all(path.parent().ok_or("capture has no parent")?)?;
        Ok(())
    }
}
