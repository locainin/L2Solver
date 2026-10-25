use std::process::Command;

use l2_audit::AssessmentProfile;
use l2_capture::InterfaceId;
use l2_cli::arguments::{
    LiveLimit, OutputFormat, ReportOptions, SourceMapping, SurveyInput, SurveyOptions,
};

fn write_policy(
    directory: &std::path::Path,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let path = directory.join("policy-v3.json");
    std::fs::write(
        &path,
        r#"{
            "schema_version": 3,
            "segments": { "trusted": {} },
            "ports": [
                { "source": "capture", "segment": "trusted", "role": "endpoint" }
            ]
        }"#,
    )?;
    Ok(path)
}

fn test_directory() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let directory = std::env::temp_dir().join(format!(
        "l2solver-source-mapping-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    std::fs::create_dir(&directory)?;
    Ok(directory)
}

#[test]
fn schema_three_uses_source_mapping() -> Result<(), Box<dyn std::error::Error>> {
    let directory = test_directory()?;
    let policy = write_policy(&directory)?;
    let result = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args([
            "assess",
            "../../tests/pcaps/lldp.pcap",
            "--policy",
            policy.to_str().ok_or("non-UTF8 temporary path")?,
            "--source",
            "0:0=capture",
            "--format",
            "json",
        ])
        .output()?;
    std::fs::remove_dir_all(directory)?;

    assert!(result.status.success());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout)?;
    let policy = report.get("policy").ok_or("missing policy")?;
    assert_eq!(policy.get("schema_version"), Some(&serde_json::json!(3)));
    Ok(())
}

#[test]
fn schema_three_policy_missing_mapping() -> Result<(), Box<dyn std::error::Error>> {
    let directory = test_directory()?;
    let policy = write_policy(&directory)?;
    let result = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args([
            "assess",
            "../../tests/pcaps/lldp.pcap",
            "--policy",
            policy.to_str().ok_or("non-UTF8 temporary path")?,
        ])
        .output()?;
    std::fs::remove_dir_all(directory)?;

    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8(result.stderr)?.contains("source mapping"));
    Ok(())
}

mod display_source {
    use std::{path::PathBuf, time::Duration};

    use super::*;

    #[test]
    fn file_uses_capture_path() -> Result<(), Box<dyn std::error::Error>> {
        let options = options(SurveyInput::File(PathBuf::from("capture.pcap")));

        let source = options.display_source();

        assert_eq!(source.label, "capture.pcap");
        assert_eq!(source.interface, None);
        assert!(options.source_labels()?.is_empty());
        Ok(())
    }

    #[test]
    fn live_default_not_interface_name() {
        let options = options(live_input());

        let source = options.display_source();

        assert_eq!(source.label, "live");
        assert_eq!(source.interface.as_deref(), Some("enp4s0"));
    }

    #[test]
    fn explicit_live_label_is_preferred() -> Result<(), Box<dyn std::error::Error>> {
        let mut options = options(live_input());
        options.source_label = Some(String::from("desk-17"));

        assert_eq!(options.display_source().label, "desk-17");
        assert_eq!(
            options.source_labels()?.label_for(InterfaceId {
                section: 0,
                index: 0,
            }),
            Some("desk-17")
        );
        Ok(())
    }

    #[test]
    fn live_mapping_labels_default_source() -> Result<(), Box<dyn std::error::Error>> {
        let mut options = options(live_input());
        options.sources.push(SourceMapping {
            section: 0,
            index: 0,
            label: String::from("closet-a"),
        });

        assert_eq!(options.display_source().label, "closet-a");
        assert_eq!(
            options.source_labels()?.label_for(InterfaceId {
                section: 0,
                index: 0,
            }),
            Some("closet-a")
        );
        Ok(())
    }

    #[test]
    fn unrelated_mapping_not_display_label() {
        let mut options = options(live_input());
        options.sources.push(SourceMapping {
            section: 0,
            index: 1,
            label: String::from("other-port"),
        });

        assert_eq!(options.display_source().label, "live");
    }

    fn live_input() -> SurveyInput {
        SurveyInput::Live {
            interface: String::from("enp4s0"),
            limit: LiveLimit::Duration(Duration::from_mins(1)),
        }
    }

    fn options(input: SurveyInput) -> SurveyOptions {
        SurveyOptions {
            input,
            policy: None,
            sources: Vec::new(),
            source_label: None,
            format: OutputFormat::Text,
            profile: AssessmentProfile::Standard,
            report: ReportOptions::default(),
        }
    }
}
