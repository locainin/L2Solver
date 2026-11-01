use std::{error::Error, sync::atomic::AtomicBool};

#[cfg(target_os = "linux")]
use std::process::Command;

use clap::Parser;
use l2_active_cli::{ActiveOutcome, Cli, execute};

#[test]
fn mpls_requires_an_interface_and_valid_bounded_label_expectation() {
    assert!(Cli::try_parse_from(["l2solver-active", "mpls", "observe"]).is_err());
    assert!(
        Cli::try_parse_from([
            "l2solver-active",
            "mpls",
            "observe",
            "--interface",
            "test0",
            "--expected-top-label",
            "1048576",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "l2solver-active",
            "mpls",
            "observe",
            "--interface",
            "test0",
            "--expected-top-label",
            "1048575",
        ])
        .is_ok()
    );
}

#[test]
fn cancelled_mpls_command_never_opens_a_helper_or_sends() -> Result<(), Box<dyn Error>> {
    let cli = Cli::try_parse_from([
        "l2solver-active",
        "mpls",
        "observe",
        "--interface",
        "l2s-no-test",
        "--format",
        "json",
    ])?;
    let mut output = Vec::new();
    assert_eq!(
        execute(&cli.active, &AtomicBool::new(true), &mut output)?,
        ActiveOutcome::Cancelled
    );
    let report: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        report.get("operation").and_then(serde_json::Value::as_str),
        Some("mpls_observe")
    );
    assert_eq!(
        report
            .pointer("/tx/attempted")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        report
            .pointer("/cleanup/state")
            .and_then(serde_json::Value::as_str),
        Some("not_started")
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "uses a proved private namespace and matching active helper"]
fn owned_veth_mpls_cli_observes_scoped_frames_and_honors_raw_opt_in() -> Result<(), Box<dyn Error>>
{
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../l2-active/tests/mpls/fixtures/veth.py");
    for raw in [false, true] {
        let output = Command::new("python3")
            .arg(&fixture)
            .arg("--")
            .arg(std::env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                "mpls::owned_namespace_mpls_cli_child",
            ])
            .env("L2_TEST_INCLUDE_RAW", if raw { "1" } else { "0" })
            .output()?;
        // The fixture's failure output can include untrusted process diagnostics
        assert!(
            output.status.success(),
            "private MPLS fixture failed; raw={raw}"
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("mpls_delivered=true no_client_send=true cleanup_confirmed=true")
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "invoked only inside the proved private MPLS fixture"]
fn owned_namespace_mpls_cli_child() -> Result<(), Box<dyn Error>> {
    use std::{fs, path::Path, process::Stdio};

    crate::namespace::assert_owned()?;
    let interface = std::env::var("L2_TEST_MPLS_INTERFACE")?;
    let fixture_dir = std::env::var_os("L2_TEST_MPLS_FIXTURE").ok_or("missing fixtures")?;
    let sync_dir = std::env::var_os("L2_TEST_MPLS_SYNC_DIR").ok_or("missing sync directory")?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let raw = std::env::var("L2_TEST_INCLUDE_RAW")? == "1";
    let index: u32 =
        fs::read_to_string(Path::new("/sys/class/net").join(&interface).join("ifindex"))?
            .trim()
            .parse()?;
    let baseline = bound_packet_sockets(index)?;
    let mut command = crate::namespace::command();
    command
        .args([
            "mpls",
            "observe",
            "--interface",
            &interface,
            "--expected-top-label",
            "101",
            "--timeout-ms",
            "2000",
            "--format",
            "json",
            "--helper",
        ])
        .arg(helper)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if raw {
        command.arg("--include-raw");
    }
    let mut child = command.spawn()?;
    if let Err(error) = await_socket(&mut child, index, baseline)
        .and_then(|()| fs::write(Path::new(&sync_dir).join("ready"), b"ready").map_err(Into::into))
    {
        let _ = child.kill();
        child.wait_with_output()?;
        return Err(error);
    }
    let output = child.wait_with_output()?;
    verify_report(&output, Path::new(&fixture_dir), raw)?;
    assert_eq!(
        bound_packet_sockets(index)?,
        baseline,
        "packet socket leaked"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn await_socket(
    child: &mut std::process::Child,
    index: u32,
    baseline: usize,
) -> Result<(), Box<dyn Error>> {
    use std::time::{Duration, Instant};

    // A newly bound packet socket proves capture opened before peer injection
    let deadline = Instant::now() + Duration::from_millis(1_500);
    while bound_packet_sockets(index)? <= baseline {
        if child.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err("MPLS helper did not bind a receive socket".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_report(
    output: &std::process::Output,
    fixture_dir: &std::path::Path,
    raw: bool,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        output.status.code(),
        Some(3),
        "unexpected MPLS observer exit status"
    );
    let stderr = std::str::from_utf8(&output.stderr)?;
    assert!(!stderr.contains("SENSITIVE-PAYLOAD"));
    let text = std::str::from_utf8(&output.stdout)?;
    let report: serde_json::Value = serde_json::from_str(text)?;
    assert_eq!(
        report.get("operation").and_then(serde_json::Value::as_str),
        Some("mpls_observe")
    );
    assert_eq!(
        report.get("status").and_then(serde_json::Value::as_str),
        Some("observed")
    );
    assert_eq!(
        report.get("completion").and_then(serde_json::Value::as_str),
        Some("incomplete")
    );
    assert_eq!(
        report
            .pointer("/details/unexpected_top_label")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        report
            .pointer("/rx/collection_packets")
            .and_then(serde_json::Value::as_u64),
        Some(3)
    );
    assert_eq!(
        report
            .pointer("/tx/attempted")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        report
            .pointer("/cleanup/confirmed")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    let observations = report
        .get("observations")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing observations")?;
    assert!(observations.iter().any(|item| {
        item.get("disposition").and_then(serde_json::Value::as_str) == Some("unsupported")
    }));
    verify_disclosure(observations, text, fixture_dir, raw)
}

#[cfg(target_os = "linux")]
fn verify_disclosure(
    observations: &[serde_json::Value],
    text: &str,
    fixture_dir: &std::path::Path,
    raw: bool,
) -> Result<(), Box<dyn Error>> {
    if raw {
        let frame = std::fs::read(fixture_dir.join("valid.bin"))?;
        let hex = frame
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(observations.iter().any(|item| {
            item.get("frame_hex").and_then(serde_json::Value::as_str) == Some(hex.as_str())
        }));
    } else {
        assert!(
            observations
                .iter()
                .all(|item| item.get("frame_hex").is_none())
        );
        for marker in ["SENSITIVE-PAYLOAD", "53454e534954495645"] {
            assert!(!text.contains(marker));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bound_packet_sockets(index: u32) -> Result<usize, Box<dyn Error>> {
    let table = std::fs::read_to_string("/proc/net/packet")?;
    let mut count = 0;
    for line in table.lines().skip(1) {
        let raw_index = line
            .split_whitespace()
            .nth(4)
            .ok_or("invalid packet socket entry")?;
        if raw_index.parse::<u32>()? == index {
            count += 1;
        }
    }
    Ok(count)
}
