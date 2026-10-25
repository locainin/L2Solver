use std::{error::Error, process::Command};

mod text {
    use super::*;

    #[test]
    fn separates_exposure_and_isolation_status() -> Result<(), Box<dyn Error>> {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(["survey", "../../tests/pcaps/lldp.pcap", "-v"])
            .output()?;
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout)?;
        assert!(text.contains("LLDP-001"));
        assert!(!text.contains("SEG-001"));
        assert!(!text.contains("INCONCLUSIVE SEG-001"));
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("core\\x1b\\x07"));
        Ok(())
    }

    #[test]
    fn renders_expected_text_sections() -> Result<(), Box<dyn Error>> {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args([
                "survey",
                "../../tests/pcaps/linux-stp.pcap",
                "-vv",
                "--evidence",
            ])
            .output()?;
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout)?;
        for section in [
            "Control-plane fingerprints: none observed",
            "Untagged STP root:",
            "Network correlations",
            "Assessment coverage",
            "Spanning tree  66% (2/3 applicable checks; 3 N/A)",
            "TESTED         STP-001",
            "50 not applicable checks omitted",
            "Indexed 1 representative packets; embedded 1 raw packets",
        ] {
            assert!(text.contains(section), "missing report section: {section}");
        }
        Ok(())
    }
}

mod policy {
    use super::*;

    #[test]
    fn policy_failure_ci_exit_mode() -> Result<(), Box<dyn Error>> {
        let directory =
            std::env::temp_dir().join(format!("l2solver-survey-finding-{}", std::process::id()));
        std::fs::create_dir(&directory)?;
        let policy = directory.join("policy.json");
        std::fs::write(&policy, br#"{"allow_untagged":false}"#)?;

        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(["survey", "../../tests/pcaps/lldp.pcap"])
            .arg("--policy")
            .arg(&policy)
            .output()?;

        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout)?.contains("VLAN-002"));

        let ci = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(["assess", "../../tests/pcaps/lldp.pcap", "--policy"])
            .arg(&policy)
            .arg("--ci")
            .output()?;

        std::fs::remove_dir_all(directory)?;
        assert_eq!(ci.status.code(), Some(4));
        assert!(String::from_utf8(ci.stdout)?.contains("VLAN-002"));
        Ok(())
    }
}

mod json {
    use super::*;

    #[test]
    fn keeps_evidence_and_excludes_passes() -> Result<(), Box<dyn Error>> {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args([
                "survey",
                "../../tests/pcaps/linux-stp.pcap",
                "--format",
                "json",
            ])
            .output()?;
        assert!(output.status.success());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(
            report.get("schema_version").ok_or("missing schema")?,
            &serde_json::json!(8)
        );
        assert_eq!(
            report
                .get("assessment_profile")
                .ok_or("missing assessment profile")?,
            &serde_json::json!("opportunistic")
        );
        let findings = report
            .get("findings")
            .and_then(serde_json::Value::as_array)
            .ok_or("missing findings")?;
        assert!(findings.iter().all(|finding| {
            finding
                .get("verdict")
                .is_none_or(|verdict| verdict != "pass")
        }));
        let stp = report
            .get("exposures")
            .and_then(serde_json::Value::as_array)
            .and_then(|exposures| {
                exposures.iter().find(|row| {
                    row.get("check_id")
                        .is_some_and(|check_id| check_id == "STP-001")
                })
            })
            .ok_or("missing STP exposure")?;
        assert!(
            !stp.get("evidence_packets")
                .ok_or("missing evidence field")?
                .as_array()
                .ok_or("missing evidence references")?
                .is_empty()
        );
        assert!(
            !report
                .get("evidence")
                .and_then(serde_json::Value::as_array)
                .ok_or("missing raw evidence")?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn full_profile_recorded_planned() -> Result<(), Box<dyn Error>> {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args([
                "assess",
                "../../tests/pcaps/lldp.pcap",
                "--profile",
                "full",
                "--format",
                "json",
            ])
            .output()?;
        assert!(output.status.success());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(
            report
                .get("assessment_profile")
                .ok_or("missing assessment profile")?,
            "full"
        );
        let dtp = report
            .get("plan")
            .and_then(|plan| plan.get("entries"))
            .ok_or("missing plan entries")?
            .as_array()
            .and_then(|entries| {
                entries.iter().find(|entry| {
                    entry
                        .get("check_id")
                        .is_some_and(|check_id| check_id == "DTP-001")
                })
            })
            .ok_or("missing DTP plan entry")?;

        assert_eq!(dtp.get("applicable").ok_or("missing applicability")?, true);
        assert_eq!(dtp.get("coverage").ok_or("missing coverage")?, "not_tested");
        assert_eq!(
            dtp.get("recommendation").ok_or("missing recommendation")?,
            true
        );
        Ok(())
    }
}

mod identity {
    use super::*;

    #[test]
    fn preserves_outer_and_claimed_macs() -> Result<(), Box<dyn Error>> {
        let source = include_bytes!("../../../tests/pcaps/lldp.pcap");
        let mut capture = source
            .get(..24)
            .ok_or("missing PCAP global header")?
            .to_vec();
        let outer = [0x02, 0, 0, 0, 0, 1];
        let claimed = [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&outer);
        frame.extend_from_slice(&0x0806_u16.to_be_bytes());
        frame.extend_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 2]);
        frame.extend_from_slice(&claimed);
        frame.extend_from_slice(&[192, 0, 2, 7]);
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&[192, 0, 2, 1]);
        let length = u32::try_from(frame.len())?;
        capture.extend_from_slice(&1_u32.to_le_bytes());
        capture.extend_from_slice(&0_u32.to_le_bytes());
        capture.extend_from_slice(&length.to_le_bytes());
        capture.extend_from_slice(&length.to_le_bytes());
        capture.extend_from_slice(&frame);

        let directory =
            std::env::temp_dir().join(format!("l2solver-identity-output-{}", std::process::id()));
        std::fs::create_dir(&directory)?;
        let path = directory.join("arp.pcap");
        std::fs::write(&path, capture)?;
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg("assess")
            .arg(&path)
            .arg("-v")
            .output()?;
        std::fs::remove_dir_all(directory)?;

        assert!(output.status.success());
        let text = String::from_utf8(output.stdout)?;
        assert!(text.contains("ARP address claim"));
        assert!(text.contains("source=02:00:00:00:00:01"));
        assert!(text.contains("claimed=00:aa:bb:cc:dd:ee"));
        assert!(text.contains("address=192.0.2.7"));
        Ok(())
    }
}

mod policy_errors {
    use super::*;

    #[test]
    fn policy_typos_malformed_capture_fail() -> Result<(), Box<dyn Error>> {
        let directory =
            std::env::temp_dir().join(format!("l2solver-survey-policy-{}", std::process::id()));
        std::fs::create_dir(&directory)?;
        let policy = directory.join("policy.json");
        std::fs::write(&policy, br#"{"alowed_vlans":[10]}"#)?;
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(["survey", "../../tests/pcaps/lldp.pcap"])
            .arg("--policy")
            .arg(&policy)
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(["survey", "../../tests/pcaps/short.pcap"])
            .output()?;
        assert_eq!(output.status.code(), Some(3));
        std::fs::remove_dir_all(directory)?;
        Ok(())
    }
}

mod html {
    use super::*;

    #[test]
    fn renders_standalone_escaped_html() -> Result<(), Box<dyn Error>> {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(["survey", "../../tests/pcaps/lldp.pcap", "--format", "html"])
            .output()?;
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout)?;
        assert!(text.starts_with("<!doctype html>"));
        assert!(text.contains("LLDP-001"));
        assert!(!text.contains("SEG-001"));
        assert!(!text.contains('\u{1b}'));
        Ok(())
    }
}

mod resource_limits {
    use super::*;

    #[test]
    fn bounds_embedded_bytes_before_output() -> Result<(), Box<dyn Error>> {
        let source = include_bytes!("../../../tests/pcaps/lldp.pcap");
        let mut capture = source
            .get(..24)
            .ok_or("missing PCAP global header")?
            .to_vec();
        let template = source.get(40..).ok_or("missing LLDP frame")?;
        let frame_length = u32::try_from(l2_capture::MAX_FRAME_LENGTH)?;
        for sequence in 0..256_u32 {
            let mut frame = template.to_vec();
            // Each source MAC creates a distinct inventory fact and representative
            // packet, while the large padding exercises the bounded report writer
            frame
                .get_mut(6..12)
                .ok_or("missing source MAC")?
                .copy_from_slice(&[
                    0x02,
                    0,
                    0,
                    0,
                    u8::try_from(sequence >> 8)?,
                    u8::try_from(sequence & 0xff)?,
                ]);
            frame.resize(l2_capture::MAX_FRAME_LENGTH, 0);
            capture.extend_from_slice(&sequence.to_le_bytes());
            capture.extend_from_slice(&0_u32.to_le_bytes());
            capture.extend_from_slice(&frame_length.to_le_bytes());
            capture.extend_from_slice(&frame_length.to_le_bytes());
            capture.extend_from_slice(&frame);
        }
        let directory = std::env::temp_dir().join(format!(
            "l2solver-survey-output-limit-{}",
            std::process::id()
        ));
        std::fs::create_dir(&directory)?;
        let path = directory.join("large-evidence.pcap");
        std::fs::write(&path, capture)?;

        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg("survey")
            .arg(&path)
            .args(["--format", "json"])
            .output()?;
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        assert!(output.stdout.len() <= 32 * 1024 * 1024);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert!(
            report
                .get("resource_limits")
                .and_then(|limits| limits.get("reached"))
                .and_then(serde_json::Value::as_array)
                .is_some_and(|limits| limits.contains(&serde_json::json!("embedded_bytes")))
        );
        assert_eq!(
            report
                .get("evidence_refs")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(256)
        );
        assert!(
            report
                .get("evidence")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|rows| rows.len() < 256)
        );

        std::fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn over_budget_without_partial_output() -> Result<(), Box<dyn Error>> {
        let source = include_bytes!("../../../tests/pcaps/lldp.pcap");
        let mut capture = source
            .get(..24)
            .ok_or("missing PCAP global header")?
            .to_vec();

        // Distinct MAC facts and ARP claims exercise the complete report serializer
        for sequence in 0..65_536_u32 {
            let source_mac = [
                0x02,
                u8::try_from(sequence >> 24)?,
                u8::try_from((sequence >> 16) & 0xff)?,
                u8::try_from((sequence >> 8) & 0xff)?,
                u8::try_from(sequence & 0xff)?,
                0x01,
            ];
            let address = [
                10,
                u8::try_from((sequence >> 16) & 0xff)?,
                u8::try_from((sequence >> 8) & 0xff)?,
                u8::try_from(sequence & 0xff)?,
            ];
            let mut frame = vec![0xff; 6];
            frame.extend_from_slice(&source_mac);
            frame.extend_from_slice(&0x0806_u16.to_be_bytes());
            frame.extend_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 2]);
            frame.extend_from_slice(&source_mac);
            frame.extend_from_slice(&address);
            frame.extend_from_slice(&[0; 6]);
            frame.extend_from_slice(&[10, 0, 0, 1]);
            let length = u32::try_from(frame.len())?;
            capture.extend_from_slice(&sequence.to_le_bytes());
            capture.extend_from_slice(&0_u32.to_le_bytes());
            capture.extend_from_slice(&length.to_le_bytes());
            capture.extend_from_slice(&length.to_le_bytes());
            capture.extend_from_slice(&frame);
        }

        let directory = std::env::temp_dir().join(format!(
            "l2solver-survey-serialized-limit-{}",
            std::process::id()
        ));
        std::fs::create_dir(&directory)?;
        let path = directory.join("many-facts.pcap");
        std::fs::write(&path, capture)?;

        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg("survey")
            .arg(&path)
            .args(["--format", "json"])
            .output()?;
        std::fs::remove_dir_all(directory)?;

        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8(output.stderr)?.contains("survey JSON output exceeds 33554432 bytes")
        );
        Ok(())
    }
}

mod inventory {
    use super::*;

    #[test]
    fn limit_returns_incomplete() -> Result<(), Box<dyn Error>> {
        let source = include_bytes!("../../../tests/pcaps/lldp.pcap");
        let mut capture = source
            .get(..24)
            .ok_or("missing PCAP global header")?
            .to_vec();
        let frame_length = 14_u32;
        for sequence in 0..=65_536_u32 {
            let [_, second, third, fourth] = sequence.to_be_bytes();
            let mut frame = vec![0xff; 6];
            frame.extend_from_slice(&[0x02, second, third, fourth, 0, 1]);
            frame.extend_from_slice(&0x88b5_u16.to_be_bytes());
            capture.extend_from_slice(&sequence.to_le_bytes());
            capture.extend_from_slice(&0_u32.to_le_bytes());
            capture.extend_from_slice(&frame_length.to_le_bytes());
            capture.extend_from_slice(&frame_length.to_le_bytes());
            capture.extend_from_slice(&frame);
        }
        let directory = std::env::temp_dir().join(format!(
            "l2solver-survey-inventory-limit-{}",
            std::process::id()
        ));
        std::fs::create_dir(&directory)?;
        let path = directory.join("many-macs.pcap");
        std::fs::write(&path, capture)?;

        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(["assess", "-vv"])
            .arg(&path)
            .output()?;
        std::fs::remove_dir_all(directory)?;

        assert_eq!(output.status.code(), Some(3));
        let text = String::from_utf8(output.stdout)?;
        assert!(text.contains("INCOMPLETE"));
        assert!(text.contains("MacFacts"));
        Ok(())
    }
}

mod live {
    #[cfg(not(feature = "live"))]
    use super::*;

    #[cfg(not(feature = "live"))]
    #[test]
    fn disabled_survey_requires_live_feature() -> Result<(), Box<dyn Error>> {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(["survey", "--interface", "eth0", "--packets", "1"])
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8(output.stderr)?.contains("--features live"));
        Ok(())
    }
}

#[path = "survey/scale.rs"]
mod scale;
