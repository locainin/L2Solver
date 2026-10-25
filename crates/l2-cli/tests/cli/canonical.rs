use l2_audit::AssessmentProfile;
use l2_cli::arguments::{
    ColorChoice, Command, LiveLimit, OutputFormat, SurveyInput, WorkbenchCommand, parse,
};
use std::{ffi::OsString, path::PathBuf, time::Duration};

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

mod assessment {
    use super::*;

    #[test]
    fn accepts_capture_and_report_options() -> Result<(), Box<dyn std::error::Error>> {
        let Command::Assess(options) = parse(&args(&[
            "assess",
            "capture.pcapng",
            "--policy",
            "customer.json",
            "--profile",
            "full",
            "--format",
            "html",
            "--output",
            "report.html",
            "--color",
            "never",
            "--fail-on-findings",
            "-vv",
            "--evidence",
        ]))?
        else {
            return Err("assessment command was not selected".into());
        };

        assert_eq!(options.input, SurveyInput::File("capture.pcapng".into()));
        assert_eq!(options.policy, Some("customer.json".into()));
        assert_eq!(options.profile, AssessmentProfile::Full);
        assert_eq!(options.format, OutputFormat::Html);
        assert_eq!(options.report.output, Some("report.html".into()));
        assert_eq!(options.report.color, ColorChoice::Never);
        assert_eq!(options.report.verbosity, 2);
        assert!(options.report.evidence);
        assert!(options.report.fail_on_findings);
        Ok(())
    }

    #[test]
    fn accepts_explicit_live_source() -> Result<(), Box<dyn std::error::Error>> {
        let Command::Assess(options) = parse(&args(&[
            "assess",
            "--interface",
            "enp4s0",
            "--duration",
            "60s",
        ]))?
        else {
            return Err("assessment command was not selected".into());
        };

        assert_eq!(
            options.input,
            SurveyInput::Live {
                interface: String::from("enp4s0"),
                limit: LiveLimit::Duration(Duration::from_mins(1)),
            }
        );
        Ok(())
    }

    #[test]
    fn accepts_explicit_live_source_label() -> Result<(), Box<dyn std::error::Error>> {
        let Command::Assess(options) = parse(&args(&[
            "assess",
            "--interface",
            "enp4s0",
            "--source-label",
            "desk-17",
            "--duration",
            "60s",
        ]))?
        else {
            return Err("assessment command was not selected".into());
        };

        assert_eq!(options.source_label.as_deref(), Some("desk-17"));
        Ok(())
    }

    #[test]
    fn live_label_rejects_capture_mapping() {
        assert!(
            parse(&args(&[
                "assess",
                "--interface",
                "enp4s0",
                "--duration",
                "60s",
                "--source-label",
                "desk-17",
                "--source",
                "0:0=desk-17",
            ]))
            .is_err()
        );
    }

    #[test]
    fn live_label_rejects_unsafe_text() {
        assert!(
            parse(&args(&[
                "assess",
                "--interface",
                "enp4s0",
                "--duration",
                "60s",
                "--source-label",
                "../desk-17",
            ]))
            .is_err()
        );
    }

    #[test]
    fn accepts_stable_policy_source_mapping() -> Result<(), Box<dyn std::error::Error>> {
        let Command::Assess(options) = parse(&args(&[
            "assess",
            "capture.pcapng",
            "--policy",
            "customer-v3.json",
            "--source",
            "0:7=office/desk-17",
        ]))?
        else {
            return Err("assessment command was not selected".into());
        };

        let [source] = options.sources.as_slice() else {
            return Err("assessment should contain exactly one source mapping".into());
        };
        assert_eq!(source.section, 0);
        assert_eq!(source.index, 7);
        assert_eq!(source.label, "office/desk-17");
        Ok(())
    }

    #[test]
    fn rejects_ambiguous_positional_live_form() {
        assert!(parse(&args(&["assess", "enp4s0", "60s"])).is_err());
        assert!(parse(&args(&["assess", "json", "capture.pcap"])).is_err());
    }

    #[test]
    fn ci_is_findings_sensitive_alias() -> Result<(), Box<dyn std::error::Error>> {
        let Command::Assess(options) = parse(&args(&["assess", "capture.pcap", "--ci"]))? else {
            return Err("assessment command was not selected".into());
        };

        assert!(options.report.fail_on_findings);
        Ok(())
    }
}

mod capture {
    use super::*;

    #[test]
    fn groups_offline_tools() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            parse(&args(&["capture", "inspect", "input.pcapng"]))?,
            Command::Inspect(PathBuf::from("input.pcapng"))
        );
        assert_eq!(
            parse(&args(&["capture", "observe", "input.pcapng"]))?,
            Command::Observe(PathBuf::from("input.pcapng"))
        );
        assert_eq!(
            parse(&args(&[
                "capture",
                "dump",
                "input.pcapng",
                "--format",
                "ndjson",
            ]))?,
            Command::Json(PathBuf::from("input.pcapng"))
        );
        Ok(())
    }

    #[test]
    fn record_requires_explicit_bounds() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            parse(&args(&[
                "capture",
                "record",
                "--interface",
                "enp4s0",
                "--packets",
                "25",
                "--output",
                "evidence.pcapng",
            ]))?,
            Command::Record {
                interface: String::from("enp4s0"),
                limit: LiveLimit::Packets(25),
                output: PathBuf::from("evidence.pcapng"),
            }
        );
        assert!(
            parse(&args(&[
                "capture",
                "record",
                "--interface",
                "enp4s0",
                "--output",
                "evidence.pcapng",
            ]))
            .is_err()
        );
        Ok(())
    }
}

mod hierarchy {
    use super::*;

    #[test]
    fn accepts_baseline_policy_wifi_commands() -> Result<(), Box<dyn std::error::Error>> {
        let baseline = parse(&args(&[
            "baseline",
            "create",
            "capture.pcap",
            "baseline.json",
            "--source",
            "0:3=office/desk-17",
        ]))?;
        let Command::BaselineCreate { sources, .. } = baseline else {
            return Err("baseline create command was not selected".into());
        };
        let [source] = sources.as_slice() else {
            return Err("baseline should contain exactly one source mapping".into());
        };
        assert_eq!(source.section, 0);
        assert_eq!(source.index, 3);
        assert_eq!(source.label, "office/desk-17");
        assert!(matches!(
            parse(&args(&["policy", "validate", "policy.json"]))?,
            Command::PolicyValidate { .. }
        ));
        assert!(matches!(
            parse(&args(&["wifi", "assess", "radio.pcapng"]))?,
            Command::Wifi(_)
        ));
        Ok(())
    }

    #[test]
    fn dev_namespace_is_parseable() -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(parse(&args(&["dev", "limits"]))?, Command::Dev(_)));
        assert!(matches!(
            parse(&args(&["dev", "decode", "ethernet", "ffffffffffff"]))?,
            Command::Dev(_)
        ));
        Ok(())
    }
}

mod expand {
    use super::*;

    #[test]
    fn accepts_zip_work_alias() -> Result<(), Box<dyn std::error::Error>> {
        for option in ["--max-zip-work-bytes", "--max-archive-output-bytes"] {
            let command = parse(&args(&[
                "workbench",
                "expand",
                "case.json",
                "--node",
                "1",
                option,
                "4096",
            ]))?;
            let Command::Workbench(WorkbenchCommand::Expand(options)) = command else {
                return Err("workbench expand command was not selected".into());
            };
            assert_eq!(options.max_zip_work_bytes.get(), 4096);
        }
        Ok(())
    }
}
