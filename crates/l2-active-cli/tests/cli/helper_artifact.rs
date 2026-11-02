use std::{error::Error, ffi::OsStr, process::Command};

#[test]
fn matching_helper_is_built_without_an_external_path() -> Result<(), Box<dyn Error>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let helper = crate::namespace::build_helper(&cargo)?;
    assert!(helper.is_absolute());
    assert!(helper.is_file());
    // An unprovisioned helper must refuse to start instead of opening a link
    assert!(!Command::new(helper).status()?.success());
    Ok(())
}

#[test]
fn matching_helper_build_failure_is_reported() {
    let result = crate::namespace::build_helper(OsStr::new("l2solver-missing-cargo-test-command"));
    assert!(result.is_err());
}

#[test]
fn namespace_children_are_not_independent_tests() -> Result<(), Box<dyn Error>> {
    let output = Command::new(std::env::current_exe()?)
        .arg("--list")
        .output()?;
    assert!(output.status.success());
    let listed = String::from_utf8(output.stdout)?;
    for line in listed.lines() {
        if !line.starts_with("helper_artifact::namespace_children_are_not_independent_tests:") {
            assert!(!line.contains("namespace_child"), "{line}");
        }
    }
    assert!(
        !listed.contains("owned_namespace_mpls_cli_child"),
        "{listed}"
    );
    assert!(
        !listed.contains("owned_namespace_helper_open_timeout"),
        "{listed}"
    );
    Ok(())
}

#[test]
fn child_dispatch_rejects_an_unproved_namespace() -> Result<(), Box<dyn Error>> {
    let output = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "dhcp::dhcp_cli_observes_owned_veth_offer_and_confirms_helper_cleanup",
        ])
        .env("L2_ACTIVE_CLI_TEST_CHILD", "dhcp")
        .env("L2_TEST_PARENT_NET_DEVICE", "0")
        .env("L2_TEST_PARENT_NET_INODE", "0")
        .output()?;
    assert!(!output.status.success());
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        diagnostics.contains("unproved private namespace"),
        "{diagnostics}"
    );
    Ok(())
}

#[test]
fn child_dispatch_rejects_missing_mode_in_a_fixture_environment() -> Result<(), Box<dyn Error>> {
    let output = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "dhcp::dhcp_cli_observes_owned_veth_offer_and_confirms_helper_cleanup",
        ])
        .env_remove("L2_ACTIVE_CLI_TEST_CHILD")
        .env("L2_TEST_PARENT_NET_DEVICE", "0")
        .env("L2_TEST_PARENT_NET_INODE", "0")
        .output()?;
    assert!(!output.status.success());
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        diagnostics.contains("missing private child mode"),
        "{diagnostics}"
    );
    Ok(())
}
