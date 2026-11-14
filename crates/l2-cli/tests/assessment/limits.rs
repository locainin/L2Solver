use super::captures;
use std::{
    error::Error,
    fs::File,
    io::{BufWriter, Write},
    process::Command,
};

#[test]
fn finding_capacity_boundary() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("roots.pcap");
    let policy = temporary.path().join("policy.json");
    std::fs::write(
        &policy,
        br#"{"allow_untagged":false,"expected_stp_root":"00:00:00:00:00:00"}"#,
    )?;
    for (packets, expected_exit, complete) in [
        (l2_audit::MAX_FINDINGS - 1, 4, true),
        (l2_audit::MAX_FINDINGS, 3, false),
    ] {
        let mut writer = BufWriter::new(File::create(&capture)?);
        writer.write_all(
            captures::LINUX_STP
                .get(..24)
                .ok_or("missing capture header")?,
        )?;
        let mut record = captures::LINUX_STP
            .get(24..)
            .ok_or("missing packet record")?
            .to_vec();
        for packet in 0..packets {
            // Alternate the root MAC to retain one transition per packet
            *record.get_mut(45).ok_or("missing root MAC suffix")? =
                if packet % 2 == 0 { 2 } else { 3 };
            writer.write_all(&record)?;
        }
        writer.flush()?;
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(["assess", "--format", "json", "--ci", "--policy"])
            .arg(&policy)
            .arg(&capture)
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(expected_exit),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(
            report.get("analysis_complete"),
            Some(&serde_json::Value::Bool(complete))
        );
        assert_eq!(
            report
                .pointer("/resource_limits/reached")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|limits| limits.iter().any(|limit| limit == "findings")),
            !complete
        );
    }
    Ok(())
}
