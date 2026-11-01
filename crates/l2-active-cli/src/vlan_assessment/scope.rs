//! Validate the two explicit interface identities and canary identity

use std::io;

use l2_capture::LinuxInterfaceIdentity;
use l2_onpath::MacAddress;

pub fn validate_pair(
    control: LinuxInterfaceIdentity,
    test: LinuxInterfaceIdentity,
    control_mac: MacAddress,
    test_mac: MacAddress,
    canary: MacAddress,
) -> io::Result<()> {
    if control == test {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "control and test must identify distinct interfaces",
        ));
    }
    // A local MAC cannot independently identify the controlled canary
    if canary == control_mac || canary == test_mac {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "canary MAC must differ from both selected local MACs",
        ));
    }
    Ok(())
}
