use super::support::{empty_capture, path_arg, run};
use std::{error::Error, fs};

#[test]
fn indexed_shared_results_malformed_keys() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("empty.pcap");
    let directory = temporary.path().join("index");
    fs::write(&capture, empty_capture())?;
    let indexed = run(
        &[
            "index",
            path_arg(&capture)?,
            "--directory",
            path_arg(&directory)?,
        ],
        b"",
    )?;
    assert!(indexed.status.success());

    let groups = run(&["indexed", path_arg(&directory)?, "shared-groups"], b"")?;
    assert!(groups.status.success());
    assert_eq!(groups.stdout.len(), 0);

    let occurrences = run(
        &[
            "indexed",
            path_arg(&directory)?,
            "shared-occurrences",
            "--kind",
            "ip_address",
            "--key-hex",
            "0a000001",
        ],
        b"",
    )?;
    assert!(occurrences.status.success());
    assert_eq!(occurrences.stdout.len(), 0);

    let malformed = run(
        &[
            "indexed",
            path_arg(&directory)?,
            "shared-occurrences",
            "--kind",
            "packet_bytes",
            "--key-hex",
            "abc",
        ],
        b"",
    )?;
    assert!(!malformed.status.success());
    Ok(())
}
