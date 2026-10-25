use l2_audit::{
    CheckPlan, Disposition, InterfaceObservation, Policy, PortBinding, SegmentExpectations,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

// Keep plan lookup failures at the test call site
#[track_caller]
pub fn entry<'a>(
    plan: &'a CheckPlan,
    check_id: &str,
) -> Result<&'a l2_audit::PlanEntry, Box<dyn Error>> {
    plan.entries
        .iter()
        .find(|entry| entry.check_id == check_id)
        .ok_or_else(|| format!("missing plan entry {check_id}").into())
}

// A small source with no protocol facts is enough for policy scope tests
pub const fn interface(index: u32) -> InterfaceObservation {
    InterfaceObservation {
        section: 0,
        index,
        frames: 1,
        macs: Vec::new(),
        vlans: Vec::new(),
        untagged_packet: Some(1),
        neighbors: Vec::new(),
        protocols: Vec::new(),
        identities: Vec::new(),
        stp_frames: 0,
        stp_packet: None,
        stp: Vec::new(),
    }
}

// Policy fixtures describe only the guest/corporate relationship used here
pub fn segmentation_policy() -> Policy {
    let mut guest = SegmentExpectations {
        allowed_vlans: Some(BTreeSet::new()),
        priority_tagged: Disposition::Unspecified,
        untagged: Disposition::Unspecified,
        max_vlan_depth: None,
        expected_stp_bridge: None,
        lldp: Disposition::Unspecified,
        stp_endpoint: Disposition::Unspecified,
        require_8021x: None,
        protocols: BTreeMap::new(),
        isolation_from: BTreeSet::new(),
        allow_to: BTreeSet::new(),
    };
    guest.isolation_from.insert("corporate".into());
    let corporate = guest.clone();
    Policy {
        schema_version: Some(2),
        segments: Some(BTreeMap::from([
            ("corporate".into(), corporate),
            ("guest".into(), guest),
        ])),
        ports: Some(vec![PortBinding {
            section: 0,
            index: 0,
            segment: "guest".into(),
            role: "access".into(),
        }]),
        ..Policy::default()
    }
}
