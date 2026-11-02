use std::{error::Error, path::Path, process::Command};

#[test]
fn vlan_capabilities_report_real_kernel_metadata_for_both_tag_protocols()
-> Result<(), Box<dyn Error>> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vlan/namespace.py");
    let output = Command::new("python3")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_l2solver-active"))
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout)?;
    assert_eq!(
        text.matches("vlan_report_passed=true cleanup_confirmed=true")
            .count(),
        2,
        "{text}"
    );
    Ok(())
}

#[test]
fn vlan_arp_reports_the_validated_scope_and_real_reply() -> Result<(), Box<dyn Error>> {
    let helper = crate::namespace::matching_helper()?;
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vlan/namespace.py");
    let output = Command::new("python3")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_l2solver-active"))
        .arg(helper)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout)?;
    assert_eq!(
        text.matches("vlan_report_passed=true cleanup_confirmed=true")
            .count(),
        2,
        "{text}"
    );
    assert_eq!(
        text.matches("wrong_vid_excluded=true reply_captured=true")
            .count(),
        2,
        "{text}"
    );
    Ok(())
}
