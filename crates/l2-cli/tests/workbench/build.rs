use super::support::{capture_with_truncated_record, empty_capture, path_arg, run};
use l2_workbench::{evidence::Case, sha256};
use serde_json::json;
use std::{
    error::Error,
    fs,
    io::Write,
    process::{Command, Stdio},
};

// Repeated frames keep output small while crossing the real default byte budget
fn repeated_frame_capture(frame: &[u8], records: u32) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = empty_capture();
    let length = u32::try_from(frame.len())?;
    for record in 0..records {
        bytes.extend_from_slice(&record.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(frame);
    }
    Ok(bytes)
}

fn large_unknown_ethernet_frame() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut frame = vec![0; 65_535];
    frame
        .get_mut(12..14)
        .ok_or("frame type is missing")?
        .copy_from_slice(&0x88b5_u16.to_be_bytes());
    Ok(frame)
}

fn capture_summary(case: &Case) -> Result<&serde_json::Value, Box<dyn Error>> {
    case.nodes()
        .iter()
        .find(|node| node.kind == "capture_summary")
        .map(|node| &node.details)
        .ok_or_else(|| "capture summary is missing".into())
}

#[test]
fn hashes_entire_valid_case() -> Result<(), Box<dyn Error>> {
    let capture = empty_capture();
    let output = run(&["build", "-"], &capture)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let case = Case::from_json(&output.stdout)?;
    assert_eq!(
        case.sources().first().map(|source| source.id.as_str()),
        Some(format!("sha256:{}", sha256(&capture)).as_str())
    );
    let inspect = run(&["inspect", "-"], &output.stdout)?;
    assert!(inspect.status.success());
    assert!(String::from_utf8(inspect.stdout)?.contains("capture_summary"));
    Ok(())
}

#[test]
fn build_output_path_noticed() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let destination = directory.path().join("case.json");
    let output = run(
        &["build", "-", "--output", path_arg(&destination)?],
        &empty_capture(),
    )?;
    assert!(output.status.success());
    assert_eq!(output.stdout.len(), 0);
    assert!(
        String::from_utf8(output.stderr)?
            .contains(&format!("Output written to {}", destination.display()))
    );
    assert!(Case::from_json(&fs::read(destination)?)?.collection_complete());
    Ok(())
}

#[test]
fn malformed_suffix_no_case_bytes() -> Result<(), Box<dyn Error>> {
    let mut bytes = empty_capture();
    bytes.extend_from_slice(&[1, 2, 3]);
    let output = run(&["build", "-"], &bytes)?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout.len(), 0);
    Ok(())
}

#[test]
fn malformed_build_names_input() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let malformed = temporary.path().join("truncated-record.pcap");
    fs::write(&malformed, capture_with_truncated_record())?;

    let result = run(&["build", path_arg(&malformed)?], b"")?;
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(result.stdout.len(), 0);
    let stderr = String::from_utf8(result.stderr)?;
    let path = malformed.display().to_string();
    assert!(stderr.contains(&path), "{stderr}");
    assert_eq!(stderr.matches(&path).count(), 1, "{stderr}");
    Ok(())
}

#[test]
fn default_byte_omissions_complete_routes() -> Result<(), Box<dyn Error>> {
    let frame = large_unknown_ethernet_frame()?;
    let capture = repeated_frame_capture(&frame, 257)?;
    let output = run(&["build", "-"], &capture)?;
    assert_eq!(output.status.code(), Some(3));
    let case = Case::from_json(&output.stdout)?;
    assert!(!case.collection_complete());
    assert_eq!(
        capture_summary(&case)?.get("frames_seen"),
        Some(&json!(257))
    );
    assert_eq!(
        capture_summary(&case)?.get("retained_frames"),
        Some(&json!(256))
    );
    assert_eq!(
        capture_summary(&case)?.get("omitted_frames"),
        Some(&json!(1))
    );
    assert_eq!(
        capture_summary(&case)?.get("reconstruction_limits"),
        Some(&serde_json::to_value(
            l2_workbench::reconstruction::Limits::default()
        )?)
    );
    assert_eq!(
        case.sources().first().map(|source| source.id.as_str()),
        Some(format!("sha256:{}", sha256(&capture)).as_str())
    );
    let warning = String::from_utf8(output.stderr)?;
    assert!(warning.contains("retained 256 of 257 capture records as packet evidence (1 omitted)"));
    assert!(warning.contains("workbench index CAPTURE --directory NEW_DIRECTORY"));
    assert!(warning.contains("workbench stream CAPTURE --directory NEW_DIRECTORY"));
    Ok(())
}

#[test]
fn explicit_byte_beyond_default_limit() -> Result<(), Box<dyn Error>> {
    let frame = large_unknown_ethernet_frame()?;
    let capture = repeated_frame_capture(&frame, 257)?;
    let maximum = (frame.len() * 257).to_string();
    let output = run(&["build", "-", "--max-bytes", &maximum], &capture)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let case = Case::from_json(&output.stdout)?;
    assert!(case.collection_complete());
    assert_eq!(
        capture_summary(&case)?.get("retained_frames"),
        Some(&json!(257))
    );
    assert_eq!(
        capture_summary(&case)?.pointer("/reconstruction_limits/bytes"),
        Some(&json!(frame.len() * 257))
    );
    assert_eq!(
        case.nodes()
            .iter()
            .filter(|node| node.kind == "packet")
            .filter_map(|node| node
                .details
                .get("record")
                .and_then(serde_json::Value::as_u64))
            .next_back(),
        Some(257)
    );
    assert_eq!(output.stderr.len(), 0);
    Ok(())
}

#[test]
fn reconstruction_unit_retained_prefix_recorded() -> Result<(), Box<dyn Error>> {
    let mut frame = super::support::ipv4_header_frame([192, 0, 2, 1], [192, 0, 2, 2]);
    frame
        .get_mut(16..18)
        .ok_or("IP length is missing")?
        .copy_from_slice(&28_u16.to_be_bytes());
    frame.extend_from_slice(&[0x9c, 0x40, 0x23, 0x28, 0, 8, 0, 0]);
    let capture = repeated_frame_capture(&frame, 3)?;

    for (maximum, retained, exit_code) in [(1, 1, 3), (3, 3, 0)] {
        let output = run(
            &["build", "-", "--max-units", &maximum.to_string()],
            &capture,
        )?;
        assert_eq!(
            output.status.code(),
            Some(exit_code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let case = Case::from_json(&output.stdout)?;
        assert_eq!(
            capture_summary(&case)?.get("retained_frames"),
            Some(&json!(retained))
        );
        assert_eq!(
            capture_summary(&case)?.pointer("/reconstruction_limits/units"),
            Some(&json!(maximum))
        );
        assert_eq!(case.collection_complete(), exit_code == 0);
    }
    Ok(())
}

#[test]
fn zero_budgets_reading_publishing_case() -> Result<(), Box<dyn Error>> {
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
        let output = run(&["build", "-", option, "0"], b"")?;
        assert_eq!(output.status.code(), Some(2), "accepted {option}=0");
        assert_eq!(output.stdout.len(), 0);
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("unexpected argument"),
            "the budget option must be recognized before its zero value is rejected"
        );
    }
    Ok(())
}

#[test]
fn incomplete_case_diagnostic_pipe_closed() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let destination = directory.path().join("case.json");
    let frame = super::support::ipv4_header_frame([192, 0, 2, 1], [192, 0, 2, 2]);
    let capture = repeated_frame_capture(&frame, 2)?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args([
            "workbench",
            "build",
            "-",
            "--max-frames",
            "1",
            "--output",
            path_arg(&destination)?,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Close diagnostics before EOF allows the child to finish building its case
    drop(child.stderr.take());
    let mut input = child.stdin.take().ok_or("capture input pipe is missing")?;
    input.write_all(&capture)?;
    drop(input);

    let output = child.wait_with_output()?;

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output.stdout.len(), 0);
    let case = Case::from_json(&fs::read(&destination)?)?;
    assert!(!case.collection_complete());
    assert_eq!(
        capture_summary(&case)?.get("omitted_frames"),
        Some(&json!(1))
    );
    Ok(())
}
