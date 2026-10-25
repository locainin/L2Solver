use l2_cli::arguments::{Command, LiveLimit, SurveyInput, parse};
use std::{ffi::OsString, time::Duration};

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

mod duration {
    use super::*;

    #[test]
    fn accepts_bounds() -> Result<(), Box<dyn std::error::Error>> {
        for (value, seconds) in [("1s", 1), ("300s", 300), ("1m", 60), ("5m", 300)] {
            let Command::Assess(options) = parse(&args(&[
                "assess",
                "--interface",
                "eth0",
                "--duration",
                value,
            ]))?
            else {
                return Err("assessment command was not selected".into());
            };
            assert_eq!(
                options.input,
                SurveyInput::Live {
                    interface: String::from("eth0"),
                    limit: LiveLimit::Duration(Duration::from_secs(seconds)),
                }
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_out_range_wrong_unit() {
        for value in ["", "0s", "301s", "6m", "1h", "-1s", "1.5m"] {
            assert!(
                parse(&args(&[
                    "assess",
                    "--interface",
                    "eth0",
                    "--duration",
                    value,
                ]))
                .is_err(),
                "accepted {value:?}"
            );
        }
    }
}

mod packets {
    use super::*;

    #[test]
    fn accepts_bounds() {
        for value in ["1", "10000"] {
            assert!(
                parse(&args(&[
                    "assess",
                    "--interface",
                    "eth0",
                    "--packets",
                    value,
                ]))
                .is_ok()
            );
        }
    }

    #[test]
    fn rejects_out_of_range() {
        for value in ["0", "10001", "-1", "one"] {
            assert!(
                parse(&args(&[
                    "assess",
                    "--interface",
                    "eth0",
                    "--packets",
                    value,
                ]))
                .is_err(),
                "accepted {value:?}"
            );
        }
    }
}

#[test]
fn single_source_single_live_limit() {
    for values in [
        vec!["assess"],
        vec!["assess", "--interface", "eth0"],
        vec!["assess", "capture.pcap", "--duration", "1s"],
        vec!["assess", "capture.pcap", "--packets", "1"],
        vec![
            "assess",
            "capture.pcap",
            "--interface",
            "eth0",
            "--duration",
            "1s",
        ],
        vec![
            "assess",
            "--interface",
            "eth0",
            "--duration",
            "1s",
            "--packets",
            "1",
        ],
    ] {
        assert!(parse(&args(&values)).is_err(), "accepted {values:?}");
    }
}
