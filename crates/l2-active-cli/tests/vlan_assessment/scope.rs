use std::{error::Error, io};

use l2_capture::LinuxInterfaceIdentity;
use l2_onpath::MacAddress;

use super::scope::validate_pair;

#[test]
fn accepts_two_distinct_interfaces_and_a_distinct_canary_mac() -> Result<(), Box<dyn Error>> {
    let first = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let second = LinuxInterfaceIdentity::new(1, 2, 3, 6, 7)?;
    let local = MacAddress::new([2, 0, 0, 0, 0, 1])?;
    let canary = MacAddress::new([2, 0, 0, 0, 0, 9])?;
    validate_pair(first, second, local, local, canary)?;
    Ok(())
}

#[test]
fn rejects_one_interface_used_for_both_roles_or_a_local_canary_mac() -> Result<(), Box<dyn Error>> {
    let first = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let second = LinuxInterfaceIdentity::new(1, 2, 3, 6, 7)?;
    let first_mac = MacAddress::new([2, 0, 0, 0, 0, 1])?;
    let second_mac = MacAddress::new([2, 0, 0, 0, 0, 2])?;
    let canary = MacAddress::new([2, 0, 0, 0, 0, 9])?;
    for result in [
        validate_pair(first, first, first_mac, second_mac, canary),
        validate_pair(first, second, first_mac, second_mac, first_mac),
        validate_pair(first, second, first_mac, second_mac, second_mac),
    ] {
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
    Ok(())
}
