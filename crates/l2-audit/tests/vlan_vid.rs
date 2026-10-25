use l2_audit::{NonZeroVid, Policy, Vid, VlanObservation};

#[test]
fn vlan_observations_distinguish_vid_types() -> Result<(), Box<dyn std::error::Error>> {
    let observation = VlanObservation {
        tags: vec![(0x8100, 0xa000), (0x88a8, 20), (0x9100, 0x0fff)],
        packet: 7,
    };

    assert_eq!(
        observation.vids().collect::<Vec<_>>(),
        [
            Vid::PriorityTagged,
            Vid::Vlan(NonZeroVid::new(20).ok_or("test VID is in range")?),
            Vid::Reserved,
        ]
    );
    Ok(())
}

#[test]
fn nonzero_vid_accepts_ordinary_identifiers() {
    assert!(NonZeroVid::new(0).is_none());
    assert_eq!(NonZeroVid::new(1).map(NonZeroVid::get), Some(1));
    assert_eq!(NonZeroVid::new(4094).map(NonZeroVid::get), Some(4094));
    assert!(NonZeroVid::new(4095).is_none());
}

#[test]
fn vlan_policy_separates_priority_tags() {
    assert!(
        Policy {
            allowed_vlans: Some(vec![0]),
            ..Policy::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Policy {
            allowed_vlans: Some(vec![1, 4094]),
            allow_priority_tagged: Some(true),
            ..Policy::default()
        }
        .validate()
        .is_ok()
    );
}
