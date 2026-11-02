use super::support::{empty_capture, path_arg, run};
use std::{error::Error, fs};

#[test]
fn output_publication_not_existing_case() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let destination = directory.path().join("case.json");
    fs::write(&destination, b"preserve")?;
    let output = run(
        &["build", "-", "--output", path_arg(&destination)?],
        &empty_capture(),
    )?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout.len(), 0);
    assert_eq!(fs::read(destination)?, b"preserve");
    Ok(())
}

#[test]
fn directory_rejects_html_early() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let index = directory.path().join("index");
    let stream = directory.path().join("stream");
    let carrier_results = directory.path().join("carrier-results");
    let commands = [
        (
            &[
                "index",
                "missing.pcap",
                "--directory",
                path_arg(&index)?,
                "--format",
                "html",
            ][..],
            &index,
        ),
        (
            &[
                "stream",
                "missing.pcap",
                "--directory",
                path_arg(&stream)?,
                "--format",
                "html",
            ][..],
            &stream,
        ),
        (
            &[
                "carrier-results",
                "discover",
                "missing-case.json",
                "--node",
                "1",
                "--plan",
                "missing-plan.json",
                "--directory",
                path_arg(&carrier_results)?,
                "--format",
                "html",
            ][..],
            &carrier_results,
        ),
    ];

    for (arguments, destination) in commands {
        let output = run(arguments, b"")?;
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8(output.stderr)?.contains("format must be text or json"));
        assert!(!destination.exists());
    }
    Ok(())
}
