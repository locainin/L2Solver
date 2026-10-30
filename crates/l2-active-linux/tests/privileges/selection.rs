use super::narrow;
use rustix::thread::{CapabilitySet, CapabilitySets};

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
