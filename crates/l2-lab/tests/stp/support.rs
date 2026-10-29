use std::error::Error;

use l2_codecs::BridgeId;
use l2_core::{EthernetFrame, FrameField};
use l2_lab::stp::{GuardExpectation, Scenario};
use l2_onpath::Budget;

pub const fn local() -> BridgeId {
    BridgeId::from_wire(0x8000, [0x02, 0, 0, 0, 0, 1])
}

pub const fn trusted() -> BridgeId {
    BridgeId::from_wire(0x4000, [0x02, 0, 0, 0, 0, 2])
}

pub const fn hostile() -> BridgeId {
    BridgeId::from_wire(0x1000, [0x02, 0, 0, 0, 0, 3])
}

pub fn frame(root: BridgeId, rapid: bool) -> Result<Vec<u8>, Box<dyn Error>> {
    // Use actual 802.3 LLC and BPDU bytes rather than a synthetic root label
    let mut payload = vec![
        0x42,
        0x42,
        0x03,
        0,
        0,
        u8::from(rapid) * 2,
        u8::from(rapid) * 2,
        0,
    ];
    payload.extend_from_slice(&root.wire_priority_and_extension().to_be_bytes());
    payload.extend_from_slice(&root.mac);
    payload.extend_from_slice(&0_u32.to_be_bytes());
    payload.extend_from_slice(&root.wire_priority_and_extension().to_be_bytes());
    payload.extend_from_slice(&root.mac);
    payload.extend_from_slice(&0x8001_u16.to_be_bytes());
    for value in [0_u16, 0x1400, 0x0200, 0x0f00] {
        payload.extend_from_slice(&value.to_be_bytes());
    }
    if rapid {
        payload.push(0);
    }
    let model = EthernetFrame {
        destination: [0x01, 0x80, 0xc2, 0, 0, 0],
        source: root.mac,
        vlan_tags: Vec::new(),
        payload: &payload,
        padding: &[],
        field: FrameField::Length(u16::try_from(payload.len())?),
    };
    let mut output = vec![0; l2_core::encoded_len(&model)?];
    l2_core::encode(&model, &mut output)?;
    Ok(output)
}

pub const fn scenario<'a>(
    control: &'a [u8],
    attack: &'a [u8],
    expectation: GuardExpectation,
) -> Scenario<'a> {
    Scenario::new(control, attack, trusted(), expectation)
}

pub fn budget() -> Result<Budget, Box<dyn Error>> {
    Ok(Budget::new(2, 256, 2)?)
}
