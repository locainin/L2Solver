#[path = "../../../tests/fixtures/capture_paths.rs"]
mod capture_paths;
#[path = "../../../tests/fixtures/captures.rs"]
pub mod captures;

use std::{
    error::Error,
    process::{Command, Stdio},
};

#[test]
fn escapes_terminal_control_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let fixtures = crate::capture_paths::CapturePaths::new()?;
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("inspect")
        .arg(fixtures.path("lldp.pcap"))
        .output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains(&format!(
        "Capture: {}",
        fixtures.path("lldp.pcap").display().to_string().escape_debug()
    )));
    assert!(text.contains("LLDP Valid"));
    assert!(text.contains("core\\x1b\\x07"));
    assert!(!text.contains('\u{1b}'));
    assert!(text.contains("frames=1 malformed=0 invalid=0 unsupported=0 truncated=0"));
    assert!(text.contains("Capture inspection: complete"));
    Ok(())
}

#[test]
fn rejects_malformed_pcapng_shows_help() -> Result<(), Box<dyn std::error::Error>> {
    let fixtures = crate::capture_paths::CapturePaths::new()?;
    let unsupported = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("inspect")
        .arg(fixtures.path("unsupported.pcapng"))
        .output()?;
    assert!(!unsupported.status.success());
    let missing = Command::new(env!("CARGO_BIN_EXE_l2solver")).output()?;
    assert!(missing.status.success());
    let help = String::from_utf8(missing.stdout)?;
    assert!(help.contains("Usage:"));
    assert!(help.contains("Network forensics and artifact recovery"));
    for command in ["survey", "baseline"] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args([command, "--help"])
            .output()?;
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout)?.contains("Usage:"));
    }
    Ok(())
}

#[test]
fn malformed_capture_names_input() -> Result<(), Box<dyn std::error::Error>> {
    let fixtures = crate::capture_paths::CapturePaths::new()?;
    let path = fixtures.path("unsupported.pcapng");
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["capture", "inspect"])
        .arg(&path)
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr)?;
    let path = path.display().to_string().escape_debug().to_string();
    assert!(stderr.contains(&path), "{stderr}");
    assert_eq!(stderr.matches(path.as_str()).count(), 1, "{stderr}");
    Ok(())
}

#[test]
fn reports_malformed_frame_and_fails() -> Result<(), Box<dyn std::error::Error>> {
    let fixtures = crate::capture_paths::CapturePaths::new()?;
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("inspect")
        .arg(fixtures.path("short.pcap"))
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("frames=1 malformed=1"));
    assert!(text.contains("Capture inspection: incomplete"));
    Ok(())
}

#[test]
fn reports_unsupported_stp_and_fails() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = crate::captures::LINUX_STP.to_vec();
    *capture
        .get_mut(24 + 16 + 19)
        .ok_or("missing STP version byte")? = 3;
    let directory = std::env::temp_dir().join(format!(
        "l2solver-inspect-unsupported-stp-{}",
        std::process::id()
    ));
    std::fs::create_dir(&directory)?;
    let path = directory.join("unsupported-stp.pcap");
    std::fs::write(&path, capture)?;

    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("inspect")
        .arg(&path)
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8(output.stdout)?.contains("unsupported=1"));

    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[test]
fn unknown_ethertype_remains_observable() -> Result<(), Box<dyn Error>> {
    let mut capture = crate::captures::LLDP.to_vec();
    capture
        .get_mut(52..54)
        .ok_or("missing EtherType")?
        .copy_from_slice(&[0x88, 0xb5]);
    let directory =
        std::env::temp_dir().join(format!("l2solver-unknown-type-{}", std::process::id()));
    std::fs::create_dir(&directory)?;
    let path = directory.join("unknown.pcap");
    std::fs::write(&path, capture)?;

    for mode in ["inspect", "json", "observe"] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg(mode)
            .arg(&path)
            .output()?;
        assert!(
            output.status.success(),
            "{mode} rejected an unknown EtherType"
        );
        let text = String::from_utf8(output.stdout)?;
        assert!(!text.contains("unsupported=1"));
        assert!(!text.contains("unsupported_stp=1"));
    }
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[test]
fn unknown_command_extra_arguments_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let fixtures = crate::capture_paths::CapturePaths::new()?;
    let path = fixtures.path("lldp.pcap");
    for args in [
        vec![
            std::ffi::OsString::from("unknown"),
            path.as_os_str().to_owned(),
        ],
        vec![
            std::ffi::OsString::from("inspect"),
            path.as_os_str().to_owned(),
            std::ffi::OsString::from("extra"),
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(args)
            .output()?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8(output.stderr)?.contains("--help"));
    }
    Ok(())
}

#[cfg(not(feature = "live"))]
#[test]
fn explains_disabled_live_commands() -> Result<(), Box<dyn std::error::Error>> {
    for arguments in [
        vec!["interfaces"],
        vec!["listen", "eth0", "1"],
        vec!["record", "eth0", "1", "evidence.pcapng"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(arguments)
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8(output.stderr)?.contains("--features live"));
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn closed_pipe_success_requested_line() -> Result<(), Box<dyn Error>> {
    let source = crate::captures::LLDP;
    let header = source.get(..24).ok_or("missing PCAP header")?;
    let record = source.get(24..).ok_or("missing PCAP record")?;
    let directory =
        std::env::temp_dir().join(format!("l2solver-broken-pipe-{}", std::process::id()));
    std::fs::create_dir(&directory)?;
    let path = directory.join("large.pcap");
    let mut capture = Vec::with_capacity(header.len() + record.len() * 10_000);
    capture.extend_from_slice(header);
    for _ in 0..10_000 {
        capture.extend_from_slice(record);
    }
    std::fs::write(&path, capture)?;

    for mode in ["inspect", "json"] {
        let mut producer = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg(mode)
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
            "{mode} treated BrokenPipe as failure"
        );
    }
    std::fs::remove_dir_all(directory)?;
    Ok(())
}
