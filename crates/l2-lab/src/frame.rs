//! Fixed-size authenticated canary frames for access ports

use l2_canary::{AgentKey, SessionKey};
use l2_core::{EthernetFrame, FrameField};
use l2_segmentation::{PlannedCanaryFrame, Probe};

use crate::{LabError, VirtualEndpoint};

// Access-port frames have two addresses and one EtherType before the canary
pub const FRAME_LEN: usize = 14 + l2_canary::WIRE_LEN;

pub fn session_key(probe: Probe, material: &[u8]) -> Result<SessionKey, LabError> {
    let canary = probe.canary()?;
    let agent_key = AgentKey::new(probe.source_agent_id(), material)?;
    Ok(SessionKey::derive(&agent_key, &canary.identity())?)
}

pub fn prepare(
    probe: Probe,
    source: VirtualEndpoint,
    destination: VirtualEndpoint,
    key: &SessionKey,
) -> Result<PlannedCanaryFrame, LabError> {
    let payload = l2_canary::encode(&probe.canary()?, key)?;
    let ethernet = EthernetFrame {
        destination: destination.mac(),
        source: source.mac(),
        vlan_tags: Vec::new(),
        payload: &payload,
        padding: &[],
        field: FrameField::EtherType(l2_canary::ETHER_TYPE),
    };
    let mut bytes = [0; FRAME_LEN];
    let written = l2_core::encode(&ethernet, &mut bytes)?;
    if written != bytes.len() {
        return Err(LabError::Invariant);
    }
    Ok(PlannedCanaryFrame::from_probe(probe, key, &bytes)?)
}
