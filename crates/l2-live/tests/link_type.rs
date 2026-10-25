#[path = "../src/metadata.rs"]
mod metadata;
#[path = "../src/packet.rs"]
mod packet;

use l2_capture::LinkType;

fn source(
    _link_type: LinkType,
) -> Result<l2_capture::LinuxInterfaceIdentity, Box<dyn std::error::Error>> {
    Ok(l2_capture::LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?)
}

#[test]
fn preserves_live_link_type() -> Result<(), Box<dyn std::error::Error>> {
    let frame = packet::capture_with_link_type(
        source(LinkType::Ieee80211)?,
        LinkType::Ieee80211,
        &[1, 2, 3],
        3,
        3,
        0,
        0,
    )?;
    assert_eq!(frame.metadata().link_type(), LinkType::Ieee80211);
    let frame = packet::capture_with_link_type(
        source(LinkType::Ieee80211Radiotap)?,
        LinkType::Ieee80211Radiotap,
        &[1, 2, 3],
        3,
        3,
        0,
        0,
    )?;
    assert_eq!(frame.metadata().link_type(), LinkType::Ieee80211Radiotap);
    let frame = packet::capture_with_link_type(
        source(LinkType::Ethernet)?,
        LinkType::Ethernet,
        &[1, 2, 3],
        3,
        3,
        0,
        0,
    )?;
    assert_eq!(frame.metadata().link_type(), LinkType::Ethernet);
    Ok(())
}
