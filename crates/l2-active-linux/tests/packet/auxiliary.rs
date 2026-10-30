use super::{Auxiliary, parse_auxiliary, qualify_auxiliary};
use l2_capture::{Direction, VlanAuxData};

#[test]
fn auxiliary_data_reports_a_hardware_stripped_vlan_tag() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = [0_u8; 20];
    bytes
        .get_mut(..4)
        .ok_or("missing status")?
        .copy_from_slice(&(16_u32 | 64).to_ne_bytes());
    bytes
        .get_mut(16..18)
        .ok_or("missing tci")?
        .copy_from_slice(&7_u16.to_ne_bytes());
    bytes
        .get_mut(18..20)
        .ok_or("missing tpid")?
        .copy_from_slice(&0x88a8_u16.to_ne_bytes());
    assert_eq!(
        parse_auxiliary(&bytes)?,
        Some(VlanAuxData {
            tpid: 0x88a8,
            tci: 7
        })
    );
    Ok(())
}

#[test]
fn auxiliary_data_distinguishes_untagged_and_incomplete_records()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(parse_auxiliary(&[0; 20])?, None);
    assert!(parse_auxiliary(&[0; 19]).is_err());
    Ok(())
}

#[test]
fn unavailable_vlan_metadata_never_qualifies_an_inbound_reply() {
    assert_eq!(
        qualify_auxiliary(Direction::Inbound, Auxiliary::Unavailable),
        (Direction::Unknown, None)
    );
    assert_eq!(
        qualify_auxiliary(Direction::Inbound, Auxiliary::Untagged),
        (Direction::Inbound, None)
    );
    let vlan = VlanAuxData {
        tpid: 0x8100,
        tci: 7,
    };
    assert_eq!(
        qualify_auxiliary(Direction::Inbound, Auxiliary::Tagged(vlan)),
        (Direction::Inbound, Some(vlan))
    );
}
