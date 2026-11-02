use std::{error::Error, path::PathBuf, process::Command};

const CHILD_MODE: &str = "L2_TEST_LIVE_NAMESPACE_CHILD";
const PARENT_FDS: &str = "L2_TEST_LIVE_PARENT_FDS";
const PARENT_UID: &str = "L2_TEST_LIVE_PARENT_UID";

fn namespace_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/receive/namespace.py")
}

pub fn run_in_private_namespace() -> Result<bool, Box<dyn Error>> {
    let fixture = namespace_fixture();
    if let Some(child) = std::env::var_os(CHILD_MODE) {
        // Verify the inherited namespace descriptors before opening capture
        if child != "1"
            || std::env::var_os(PARENT_FDS).is_none()
            || std::env::var_os(PARENT_UID).is_none()
        {
            return Err("unproved private namespace: missing parent descriptors".into());
        }
        let output = Command::new("python3")
            .arg(&fixture)
            .arg("--verify")
            .output()
            .map_err(|error| format!("unproved private namespace: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "unproved private namespace: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        return Ok(true);
    }

    // The fixture waits for the isolated child and checks that the test ran
    let output = Command::new("python3")
        .arg(fixture)
        .arg("--run")
        .arg(std::env::current_exe()?)
        .output()?;
    if !output.status.success()
        || !String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line == "deadline_test_passed=true")
    {
        return Err(format!(
            "isolated deadline fixture failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(false)
}

fn assert_unproved_child_is_rejected(mode: &str) -> Result<(), Box<dyn Error>> {
    let output = Command::new("python3")
        .arg(namespace_fixture())
        .arg(format!("--probe-{mode}"))
        .arg(std::env::current_exe()?)
        .output()?;
    assert!(
        output.status.success()
            && String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line == "namespace_rejected=true"),
        "child with {mode} namespace proof was not rejected: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn child_without_parent_descriptors_is_rejected_before_capture() -> Result<(), Box<dyn Error>> {
    assert_unproved_child_is_rejected("missing")
}

#[test]
fn child_with_current_namespace_descriptors_is_rejected_before_capture()
-> Result<(), Box<dyn Error>> {
    assert_unproved_child_is_rejected("same")
}

#[test]
fn child_with_current_pid_namespace_is_rejected_before_capture() -> Result<(), Box<dyn Error>> {
    assert_unproved_child_is_rejected("pid")
}
