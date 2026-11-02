use std::{error::Error, path::Path, process::Command};

#[test]
fn global_ndp_fixture_rejects_a_missing_libtest_child() -> Result<(), Box<dyn Error>> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ndp/fixtures/global_veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args(["--ignored", "--exact", "missing_namespace_child"])
        .env("L2_TEST_NDP_GLOBAL_CASE", "no_route")
        .output()?;
    assert!(
        !output.status.success(),
        "zero executed child tests were accepted"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("expected one child test"));
    Ok(())
}
