use std::{error::Error, process::Command};

#[cfg(not(feature = "dev-fixtures"))]
#[test]
fn fixture_inspection_is_unavailable_without_dev_fixtures() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["dev", "fixture", "inspect", "lldp"])
        .output()?;

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("fixture"), "{stderr}");
    assert!(stderr.contains("Usage:"), "{stderr}");
    Ok(())
}

#[cfg(feature = "dev-fixtures")]
#[test]
fn inspection_reports_known_fixtures_from_an_empty_working_directory() -> Result<(), Box<dyn Error>>
{
    let working_directory = tempfile::tempdir()?;
    for (name, length) in [("lldp", 81), ("linux-stp", 92)] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(["dev", "fixture", "inspect", name])
            .current_dir(working_directory.path())
            .output()?;

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout)?,
            format!("fixture={name} bytes={length}\n")
        );
    }
    Ok(())
}

#[cfg(feature = "dev-fixtures")]
#[test]
fn inspection_rejects_an_unknown_fixture_name() -> Result<(), Box<dyn Error>> {
    let working_directory = tempfile::tempdir()?;
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["dev", "fixture", "inspect", "unknown"])
        .current_dir(working_directory.path())
        .output()?;

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout.len(), 0);
    assert!(String::from_utf8(output.stderr)?.contains("unknown fixture"));
    Ok(())
}
