#![cfg(not(feature = "live"))]

use std::{error::Error, process::Command};

#[test]
fn live_disabled() -> Result<(), Box<dyn Error>> {
    for (arguments, message) in [
        (vec!["interfaces"], "live capture is optional"),
        (vec!["listen", "eth0", "1"], "live capture is optional"),
        (
            vec!["record", "eth0", "1", "evidence.pcapng"],
            "live recording is optional",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(arguments)
            .output()?;
        assert!(!output.status.success());
        assert!(
            String::from_utf8(output.stderr)?.contains(message),
            "disabled command did not explain the required feature"
        );
    }
    Ok(())
}
