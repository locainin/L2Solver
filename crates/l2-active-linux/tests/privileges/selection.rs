use super::{confirm, drop_all, narrow, restrict_startup};
use rustix::thread::{self, CapabilitySet, CapabilitySets};
use std::{io, process::Command};

const CHILD_MODE: &str = "L2_ACTIVE_PRIVILEGE_TEST_CHILD";

fn run_isolated(test: &str) -> io::Result<()> {
    let output = Command::new(std::env::current_exe()?)
        .arg("--exact")
        .arg(format!("privileges::tests::{test}"))
        .arg("--nocapture")
        .env(CHILD_MODE, test)
        .output()?;
    assert!(
        output.status.success(),
        "isolated test failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
        "isolated test did not run: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    Ok(())
}

fn is_child(test: &str) -> io::Result<bool> {
    match std::env::var(CHILD_MODE) {
        Ok(value) if value == test => Ok(true),
        Ok(_) => Err(io::Error::other("unexpected privilege test child mode")),
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(error) => Err(io::Error::other(error)),
    }
}

#[test]
fn startup_keeps_only_already_effective_packet_capability() {
    let existing = CapabilitySets {
        effective: CapabilitySet::NET_RAW | CapabilitySet::NET_ADMIN,
        permitted: CapabilitySet::NET_RAW | CapabilitySet::NET_ADMIN,
        inheritable: CapabilitySet::NET_ADMIN,
    };
    let selected = narrow(existing);
    assert_eq!(selected.effective, CapabilitySet::NET_RAW);
    assert_eq!(selected.permitted, CapabilitySet::NET_RAW);
    assert_eq!(selected.inheritable, CapabilitySet::empty());
}

#[test]
fn startup_does_not_activate_a_capability_missing_from_effective_set() {
    let existing = CapabilitySets {
        effective: CapabilitySet::empty(),
        permitted: CapabilitySet::NET_RAW,
        inheritable: CapabilitySet::empty(),
    };
    assert_eq!(narrow(existing).effective, CapabilitySet::empty());
}

#[test]
fn startup_narrows_capabilities_and_confirms_the_result() -> io::Result<()> {
    const TEST: &str = "startup_narrows_capabilities_and_confirms_the_result";
    if !is_child(TEST)? {
        return run_isolated(TEST);
    }

    let original = thread::capabilities(None)?;
    if !thread::no_new_privs()? {
        assert!(confirm(original).is_err());
    }
    restrict_startup()?;
    let expected = narrow(original);
    assert_eq!(thread::capabilities(None)?, expected);
    assert!(thread::no_new_privs()?);
    confirm(expected)?;

    // An otherwise valid worker must still reject a capability mismatch
    let mut wrong = expected;
    wrong.effective ^= CapabilitySet::NET_RAW;
    assert!(confirm(wrong).is_err());
    Ok(())
}

#[test]
fn dropping_capabilities_clears_every_set() -> io::Result<()> {
    const TEST: &str = "dropping_capabilities_clears_every_set";
    if !is_child(TEST)? {
        return run_isolated(TEST);
    }

    thread::set_no_new_privs(true)?;
    drop_all()?;
    assert_eq!(
        thread::capabilities(None)?,
        CapabilitySets {
            effective: CapabilitySet::empty(),
            permitted: CapabilitySet::empty(),
            inheritable: CapabilitySet::empty(),
        }
    );
    assert!(thread::no_new_privs()?);
    Ok(())
}
