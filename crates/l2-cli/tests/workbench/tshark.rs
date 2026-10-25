use super::{
    TsharkOptions, decode_packets, prepare_capture_from_at,
    process::{self, ProcessError},
    run, snapshot_with_clock, verify_source_unchanged,
};
use crate::arguments::{WorkbenchCommand, parse};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

#[cfg(unix)]
#[path = "tshark/receipt.rs"]
mod receipt;

fn assert_error_contains<T, E: std::fmt::Display>(
    result: Result<T, E>,
    expected: &str,
) -> Result<(), Box<dyn Error>> {
    let message = match result {
        Err(error) => error.to_string(),
        Ok(_) => return Err(format!("expected error containing {expected:?}, got success").into()),
    };
    assert!(
        message.contains(expected),
        "expected error containing {expected:?}, got {message:?}"
    );
    Ok(())
}

fn json_field<'a>(
    value: &'a serde_json::Value,
    name: &str,
) -> Result<&'a serde_json::Value, Box<dyn Error>> {
    value
        .get(name)
        .ok_or_else(|| format!("required JSON field {name:?} is missing").into())
}

#[test]
fn tshark_json_identity_reassembled_fields() -> Result<(), Box<dyn Error>> {
    let packet_json = br#"[
        {"_source":{"layers":{"frame":{"frame.number":"1"},"tcp":{"tcp.reassembled.data":"abcd"}}}},
        {"_source":{"layers":{"frame":{"frame.number":"2"},"ip":{"ip.src":"192.0.2.1"}}}}
    ]"#;

    let packets = decode_packets(packet_json)?;

    assert_eq!(packets.len(), 2);
    let first_packet = packets.first().ok_or("first decoded packet missing")?;
    assert_eq!(first_packet.packet_number, 1);
    assert_eq!(
        first_packet
            .fields
            .get("tcp")
            .and_then(|tcp| tcp.get("tcp.reassembled.data"))
            .and_then(serde_json::Value::as_str),
        Some("abcd")
    );
    assert_eq!(
        first_packet.reassembled_fields,
        std::collections::BTreeSet::from(["tcp.reassembled.data".to_owned()])
    );
    let second_packet = packets.get(1).ok_or("second decoded packet missing")?;
    assert_eq!(second_packet.packet_number, 2);
    assert!(serde_json::to_value(first_packet)?.get("ranges").is_none());
    Ok(())
}

#[test]
fn tshark_json_ambiguous_packet_identity() {
    for bytes in [
        br#"{"not":"an array"}"#.as_slice(),
        br#"[{"_source":{"layers":{"frame":{"frame.number":"0"}}}}]"#,
        br#"[{"_source":{"layers":{"frame":{}}}]"#,
        br#"[{"_source":{"layers":{"frame":{"frame.number":"2"}}}},{"_source":{"layers":{"frame":{"frame.number":"1"}}}}]"#,
    ] {
        assert!(decode_packets(bytes).is_err(), "accepted {}", String::from_utf8_lossy(bytes));
    }
}

#[test]
fn isolated_profile_missing_changed_settings() -> Result<(), Box<dyn Error>> {
    let preferences = concat!(
        "# L2Solver isolated offline profile\n",
        "gui.packet_list_show_related: FALSE\n",
        "ip.defragment: TRUE\n",
        "ipv6.defragment: TRUE\n",
        "tcp.desegment_tcp_streams: TRUE\n",
        "http.desegment_headers: TRUE\n",
        "http.desegment_body: TRUE\n",
        "tls.desegment_ssl_records: TRUE\n",
        "tls.desegment_ssl_application_data: TRUE\n",
    );
    let verified = super::verify_effective_preferences(preferences.as_bytes())?;

    assert_eq!(
        verified
            .get("gui.packet_list_show_related")
            .map(String::as_str),
        Some("FALSE")
    );
    assert_eq!(
        verified.get("ip.defragment").map(String::as_str),
        Some("TRUE")
    );
    assert!(
        super::verify_effective_preferences(
            b"#gui.packet_list_show_related: TRUE\nip.defragment: TRUE\n"
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn tshark_budgets_old_arbitrary_ceiling() -> Result<(), Box<dyn Error>> {
    let arguments = [
        "workbench",
        "tshark",
        "capture.pcap",
        "--timeout-seconds",
        "5000",
        "--max-input-mib",
        "20000",
        "--max-metadata-mib",
        "20000",
        "--max-output-mib",
        "20000",
        "--max-diagnostics-mib",
        "20000",
    ];

    let command = parse(&arguments.map(std::ffi::OsString::from))?;
    let crate::arguments::Command::Workbench(workbench) = command else {
        return Err("TShark subcommand did not parse".into());
    };
    let WorkbenchCommand::Tshark(options) = workbench else {
        return Err("TShark subcommand did not produce TShark options".into());
    };
    assert_eq!(options.timeout_seconds, 5000);
    assert_eq!(options.max_input_mib, 20_000);
    assert_eq!(options.max_metadata_mib, 20_000);
    assert_eq!(options.max_output_mib, 20_000);
    assert_eq!(options.max_diagnostics_mib, 20_000);
    Ok(())
}

#[test]
fn changed_source_rejected_tool_execution() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let source_path = directory.path().join("capture.pcap");
    fs::write(&source_path, b"first snapshot")?;
    let mut source = fs::File::open(&source_path)?;
    let digest = l2_workbench::sha256(&fs::read(&source_path)?);

    fs::write(&source_path, b"second snapshot")?;

    assert!(verify_source_unchanged(&mut source, &source_path, &digest, 14).is_err());
    Ok(())
}

#[test]
fn absent_tshark_error_without_dependency() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture = directory.path().join("input.pcap");
    fs::write(&capture, b"offline bytes")?;
    let options = TsharkOptions {
        capture,
        executable: directory.path().join("missing-tshark"),
        tls_keylog: None,
        output: None,
        timeout_seconds: 1,
        max_input_mib: 1,
        max_metadata_mib: 1,
        max_output_mib: 1,
        max_diagnostics_mib: 1,
    };

    assert_error_contains(run(&options, &mut Vec::new()), "not found")?;
    Ok(())
}

#[test]
fn tshark_capture_snapshot_uses_preparation_deadline() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture = directory.path().join("input.pcap");
    fs::write(&capture, b"offline bytes")?;
    let preparation = super::CapturePreparation {
        capture,
        executable: std::env::current_exe()?,
        keylog: None,
        timeout: Duration::from_secs(1),
        timeout_seconds: 1,
        input_maximum: u64::MAX,
        metadata_maximum: 1024,
        output_maximum: 1024,
        diagnostic_maximum: 1024,
    };
    let started_at = Instant::now()
        .checked_sub(Duration::from_secs(2))
        .ok_or("test clock could not represent a prior instant")?;

    assert_error_contains(
        prepare_capture_from_at(preparation, None, started_at),
        "time budget",
    )?;
    Ok(())
}

#[test]
fn tshark_capture_snapshot_stops_when_copy_deadline_expires() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture = directory.path().join("input.pcap");
    fs::write(&capture, b"offline bytes")?;
    let snapshot_directory = directory.path().join("snapshot");
    fs::create_dir(&snapshot_directory)?;
    let started_at = Instant::now();
    let deadline = started_at
        .checked_add(Duration::from_secs(1))
        .ok_or("test deadline could not be represented")?;
    let mut clock_checks = 0;

    assert_error_contains(
        snapshot_with_clock(
            &capture,
            &snapshot_directory,
            "capture.bin",
            u64::MAX,
            "capture",
            deadline,
            || {
                clock_checks += 1;
                if clock_checks <= 3 {
                    started_at
                } else {
                    deadline
                }
            },
        ),
        "time budget",
    )?;
    assert_eq!(clock_checks, 4);
    assert_eq!(
        fs::metadata(snapshot_directory.join("capture.bin"))?.len(),
        0
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn tshark_process_timed_out_child() {
    let started = std::time::Instant::now();

    let result = run_shell("exec sleep 2", Duration::from_millis(100), 1024, 1024);

    assert!(matches!(result, Err(ProcessError::TimedOut)));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[cfg(unix)]
#[test]
fn tshark_process_holding_output_pipes() {
    let started = std::time::Instant::now();

    let result = run_shell("sleep 2 & exit", Duration::from_millis(100), 1024, 1024);

    assert!(matches!(result, Err(ProcessError::TimedOut)));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[cfg(unix)]
#[test]
fn tshark_process_oversized_output_truncating() {
    let result = run_shell("printf 123456789", Duration::from_secs(2), 8, 1024);

    assert!(
        matches!(result, Err(ProcessError::OutputLimit)),
        "unexpected process result: {}",
        match &result {
            Ok(output) => format!(
                "success with {} stdout bytes, {} stderr bytes, exit status {}",
                output.stdout.len(),
                output.stderr.len(),
                output.status
            ),
            Err(error) => error.to_string(),
        }
    );
}

#[cfg(unix)]
#[test]
fn tshark_process_oversized_diagnostics_truncating() {
    let result = run_shell("printf 123456789 >&2", Duration::from_secs(2), 1024, 8);

    assert!(matches!(result, Err(ProcessError::OutputLimit)));
}

#[test]
fn tshark_enrichment_when_tshark_available() -> Result<(), Box<dyn Error>> {
    if Command::new("tshark").arg("--version").output().is_err() {
        return Ok(());
    }
    let capture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/pcaps/lldp.pcap")
        .canonicalize()?;
    let temporary = tempfile::tempdir()?;
    let keylog = temporary.path().join("keys.log");
    fs::write(&keylog, b"# Explicit key log for receipt coverage\n")?;
    let options = TsharkOptions {
        capture: capture.clone(),
        executable: PathBuf::from("tshark"),
        tls_keylog: Some(keylog.clone()),
        output: None,
        timeout_seconds: 30,
        max_input_mib: 1,
        max_metadata_mib: 1,
        max_output_mib: 16,
        max_diagnostics_mib: 1,
    };
    let mut output = Vec::new();

    run(&options, &mut output)?;

    let report: serde_json::Value = serde_json::from_slice(&output)?;
    serde_json::from_value::<l2_workbench::tshark::TsharkReport>(report.clone())?.validate()?;
    let source_bytes = fs::read(capture)?;
    let expected_source_hash = format!("{:x}", Sha256::digest(&source_bytes));
    assert_source_and_provenance(&report, &expected_source_hash)?;
    assert_tool_receipt(&report, &keylog)?;
    Ok(())
}

fn assert_source_and_provenance(
    report: &serde_json::Value,
    expected_source_hash: &str,
) -> Result<(), Box<dyn Error>> {
    let source = json_field(report, "source")?;
    assert_eq!(
        json_field(source, "sha256")?.as_str(),
        Some(expected_source_hash)
    );
    let packets = json_field(report, "packets")?
        .as_array()
        .ok_or("decoded packets must be a JSON array")?;
    let first_packet = packets
        .first()
        .ok_or("TShark returned no decoded packets")?;
    assert_eq!(json_field(first_packet, "packet_number")?.as_u64(), Some(1));
    let provenance = json_field(report, "provenance")?;
    assert_eq!(
        json_field(provenance, "source_change_verified")?.as_bool(),
        Some(true)
    );
    assert_eq!(
        json_field(provenance, "tool_derived")?.as_bool(),
        Some(true)
    );
    assert_eq!(
        json_field(provenance, "tls_decryption")?.as_str(),
        Some("explicit_keylog")
    );
    Ok(())
}

fn assert_tool_receipt(report: &serde_json::Value, keylog: &Path) -> Result<(), Box<dyn Error>> {
    let tool = json_field(report, "tool")?;
    let executable = json_field(tool, "executable")?
        .as_str()
        .ok_or("resolved TShark path missing")?;
    assert!(Path::new(executable).is_absolute());
    assert_eq!(
        json_field(tool, "executable_requested")?.as_str(),
        Some("tshark")
    );
    assert_eq!(
        json_field(tool, "executable_sha256")?
            .as_str()
            .map(str::len),
        Some(64)
    );
    let budgets = json_field(tool, "budgets")?;
    assert_eq!(
        json_field(budgets, "metadata_stdout_bytes_per_phase")?.as_u64(),
        Some(1024 * 1024)
    );
    assert_eq!(
        json_field(budgets, "diagnostic_bytes_per_phase")?.as_u64(),
        Some(1024 * 1024)
    );
    let invocations = json_field(tool, "invocations")?;
    let invocation_list = invocations
        .as_array()
        .ok_or("tool invocations must be a JSON array")?;
    let version_invocation = invocation_list
        .first()
        .ok_or("version invocation is missing")?;
    let version_arguments = json_field(version_invocation, "argv")?
        .as_array()
        .ok_or("version arguments must be a JSON array")?;
    assert_eq!(
        version_arguments
            .first()
            .and_then(serde_json::Value::as_str),
        Some("-n")
    );
    let preferences = json_field(tool, "verified_profile_preferences")?;
    assert_eq!(
        json_field(preferences, "gui.packet_list_show_related")?.as_str(),
        Some("FALSE")
    );
    let decode_invocation = invocation_list
        .iter()
        .find(|invocation| {
            invocation.get("phase").and_then(serde_json::Value::as_str) == Some("decode")
        })
        .ok_or("decode invocation is missing")?;
    let decode_arguments = json_field(decode_invocation, "argv")?
        .as_array()
        .ok_or("decode arguments must be a JSON array")?;
    assert!(decode_arguments.windows(2).any(|pair| {
        pair.first().and_then(serde_json::Value::as_str) == Some("-o")
            && pair.get(1).and_then(serde_json::Value::as_str)
                == Some("tls.keylog_file:<keylog-snapshot>")
    }));
    let profile = json_field(tool, "profile")?;
    let tls_keylog = json_field(profile, "tls_keylog")?;
    let expected_keylog_hash = format!("{:x}", Sha256::digest(fs::read(keylog)?));
    assert_eq!(
        json_field(tls_keylog, "sha256")?.as_str(),
        Some(expected_keylog_hash.as_str())
    );
    assert!(json_field(tool, "plugins")?.as_array().is_some());
    assert!(json_field(report, "output_sha256")?.as_str().is_some());
    Ok(())
}

#[cfg(unix)]
fn run_shell(
    command: &str,
    timeout: Duration,
    stdout_maximum: usize,
    stderr_maximum: usize,
) -> Result<process::Output, ProcessError> {
    let arguments = [OsString::from("-c"), OsString::from(command)];
    process::run(
        Path::new("/bin/sh"),
        &arguments,
        &[],
        timeout,
        stdout_maximum,
        stderr_maximum,
    )
}
