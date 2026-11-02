#[path = "../../../tests/fixtures/capture_paths.rs"]
mod capture_paths;
#[path = "../../../tests/fixtures/captures.rs"]
pub mod captures;

use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

mod text {
    use super::*;

    #[test]
    fn puts_security_result_before_detail() -> Result<(), Box<dyn std::error::Error>> {
        let fixtures = crate::capture_paths::CapturePaths::new()?;
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg("assess")
            .arg(fixtures.path("lldp.pcap"))
            .output()?;

        assert!(output.status.success());
        let text = String::from_utf8(output.stdout)?;
        for heading in [
            "L2Solver assessment",
            "Findings",
            "Attack surface",
            "Not tested",
        ] {
            assert!(text.contains(heading), "missing {heading}");
        }
        assert!(text.find("Findings").is_some_and(|findings| {
            text.find("Attack surface")
                .is_some_and(|surface| findings < surface)
        }));
        assert!(text.contains("LLDP neighbor metadata is visible"));
        assert!(text.contains("Capture"));
        assert!(text.contains("COMPLETE"));
        assert!(text.contains("Use -v for inventory and packet references"));
        assert!(!text.contains("\nInventory\n"));
        assert!(!text.contains("SEG-001"));
        assert!(!text.contains("NOT APPLICABLE"));
        assert!(!text.contains("POTENTIAL LLDP-001"));
        assert!(!text.contains("INCONCLUSIVE SEG-001"));
        Ok(())
    }

    #[test]
    fn verbosity_reveals_inventory_and_diagnostics() -> Result<(), Box<dyn std::error::Error>> {
        let fixtures = crate::capture_paths::CapturePaths::new()?;
        let verbose = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg("assess")
            .arg(fixtures.path("lldp.pcap"))
            .arg("-v")
            .output()?;
        assert!(verbose.status.success());
        let text = String::from_utf8(verbose.stdout)?;
        assert!(text.contains("Inventory"));
        assert!(text.contains("Assessment coverage"));

        let diagnostic = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg("assess")
            .arg(fixtures.path("lldp.pcap"))
            .args(["-vv", "--evidence"])
            .output()?;
        assert!(diagnostic.status.success());
        let text = String::from_utf8(diagnostic.stdout)?;
        assert!(text.contains("Control-plane fingerprints"));
        assert!(text.contains("Evidence index"));
        Ok(())
    }

    #[test]
    fn no_color_overrides_explicit_color() -> Result<(), Box<dyn std::error::Error>> {
        let fixtures = crate::capture_paths::CapturePaths::new()?;
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg("assess")
            .arg(fixtures.path("lldp.pcap"))
            .args(["--color", "always"])
            .env("NO_COLOR", "1")
            .output()?;
        assert!(output.status.success());
        assert!(!output.stdout.contains(&0x1b));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn closed_consumer_success_exit_status() -> Result<(), Box<dyn std::error::Error>> {
        let fixtures = crate::capture_paths::CapturePaths::new()?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_l2solver"));
        command
            .arg("assess")
            .arg(fixtures.path("lldp.pcap"))
            .arg("-vv");
        assert_eq!(run_with_closed_stdout(&mut command)?, Some(0));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn closed_consumer_incomplete_exit_status() -> Result<(), Box<dyn std::error::Error>> {
        let directory = std::env::temp_dir().join(format!(
            "l2solver-assessment-incomplete-pipe-{}",
            std::process::id()
        ));
        std::fs::create_dir(&directory)?;
        let capture = directory.join("incomplete.pcap");
        let mut bytes = crate::captures::LLDP.to_vec();
        // A one-byte second record makes the report retain a finding and mark quality incomplete
        bytes.extend_from_slice(&[
            2, 0, 0, 0, // seconds
            0, 0, 0, 0, // microseconds
            1, 0, 0, 0, // captured length
            1, 0, 0, 0, // original length
            0, // malformed Ethernet payload
        ]);
        std::fs::write(&capture, bytes)?;

        let mut command = Command::new(env!("CARGO_BIN_EXE_l2solver"));
        command.args(["assess", "-vv"]).arg(&capture);
        let status = run_with_closed_stdout(&mut command)?;
        std::fs::remove_dir_all(directory)?;
        assert_eq!(status, Some(3));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn closed_consumer_findings_exit_status() -> Result<(), Box<dyn std::error::Error>> {
        let fixtures = crate::capture_paths::CapturePaths::new()?;
        let directory = std::env::temp_dir().join(format!(
            "l2solver-assessment-finding-pipe-{}",
            std::process::id()
        ));
        std::fs::create_dir(&directory)?;
        let policy = directory.join("policy.json");
        std::fs::write(&policy, br#"{"allow_untagged":false}"#)?;

        let mut command = Command::new(env!("CARGO_BIN_EXE_l2solver"));
        command
            .arg("assess")
            .arg(fixtures.path("lldp.pcap"))
            .arg("--ci")
            .arg("--policy")
            .arg(&policy);
        let status = run_with_closed_stdout(&mut command)?;
        std::fs::remove_dir_all(directory)?;
        assert_eq!(status, Some(4));
        Ok(())
    }

    #[test]
    fn output_file_atomic_never_overwritten() -> Result<(), Box<dyn std::error::Error>> {
        let fixtures = crate::capture_paths::CapturePaths::new()?;
        let directory =
            std::env::temp_dir().join(format!("l2solver-report-output-{}", std::process::id()));
        std::fs::create_dir(&directory)?;
        let report = directory.join("report.txt");
        let run = || {
            Command::new(env!("CARGO_BIN_EXE_l2solver"))
                .arg("assess")
                .arg(fixtures.path("lldp.pcap"))
                .arg("--output")
                .arg(&report)
                .output()
        };

        let first = run()?;
        assert!(first.status.success());
        assert!(first.stdout.is_empty());
        assert!(
            String::from_utf8(first.stderr)?
                .contains(&report.display().to_string().escape_debug().to_string())
        );
        assert!(std::fs::read_to_string(&report)?.contains("L2Solver assessment"));
        assert_eq!(run()?.status.code(), Some(1));
        assert!(!PathBuf::from(&report).with_extension("tmp").exists());
        std::fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[cfg(unix)]
    fn run_with_closed_stdout(
        command: &mut Command,
    ) -> Result<Option<i32>, Box<dyn std::error::Error>> {
        command.stdout(Stdio::piped());
        let mut producer = command.spawn()?;
        // Dropping the only reader closes the pipe before the report flushes
        drop(producer.stdout.take().ok_or("missing stdout")?);
        Ok(producer.wait()?.code())
    }
}

mod json {
    use super::*;

    #[test]
    fn keeps_coverage_out_of_findings() -> Result<(), Box<dyn std::error::Error>> {
        let fixtures = crate::capture_paths::CapturePaths::new()?;
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg("assess")
            .arg(fixtures.path("lldp.pcap"))
            .args(["--format", "json"])
            .output()?;

        assert!(output.status.success());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert!(
            report
                .get("exposures")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| !values.is_empty())
        );
        assert!(
            report
                .get("coverage")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| !values.is_empty())
        );
        assert!(
            report
                .get("plan")
                .and_then(|plan| plan.get("recommendations"))
                .is_some_and(serde_json::Value::is_array)
        );
        assert!(
            report
                .get("findings")
                .and_then(serde_json::Value::as_array)
                .is_some_and(Vec::is_empty)
        );
        Ok(())
    }
}
