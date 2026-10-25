use l2_cli::arguments::{self, Command};
use std::{error::Error, path::Path};

#[test]
fn extraction_names_select_the_existing_capture_handler() -> Result<(), Box<dyn Error>> {
    for spelling in ["extract", "export"] {
        let command =
            arguments::parse_from(["l2solver", spelling, "traffic.pcapng", "-o", "recovered"])?;
        let Command::Export(options) = command else {
            return Err(format!("{spelling} did not select capture extraction").into());
        };
        assert_eq!(options.capture, Path::new("traffic.pcapng"));
        assert_eq!(options.output.as_deref(), Some(Path::new("recovered")));
        assert!(!options.require_tshark);
    }
    Ok(())
}

#[test]
fn extraction_accepts_explicit_required_tshark_policy() -> Result<(), Box<dyn Error>> {
    for spelling in ["extract", "export"] {
        let command =
            arguments::parse_from(["l2solver", spelling, "traffic.pcap", "--require-tshark"])?;
        let Command::Export(options) = command else {
            return Err(format!("{spelling} did not select capture extraction").into());
        };
        assert!(options.require_tshark);
    }
    Ok(())
}

#[test]
fn extraction_keeps_assessment_profiles_out_of_its_policy() {
    let result = arguments::parse_from([
        "l2solver",
        "extract",
        "traffic.pcap",
        "--profile",
        "opportunistic",
    ]);
    assert!(result.is_err_and(|error| error.kind() == clap::error::ErrorKind::UnknownArgument));
}
