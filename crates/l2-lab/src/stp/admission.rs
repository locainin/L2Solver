//! Validate BPDU inputs and admit the complete virtual workload

use l2_codecs::{BridgeId, StpBpduType, StpFrame, StpTimers};
use l2_core::{EthernetFrame, FrameField};
use l2_onpath::{Budget, MacAddress};
use l2_scenario::{Schedule, Stimulus};

use super::{Error, Scenario};

/// Largest accepted complete modeled Ethernet frame in this narrow scenario
pub const MAX_FRAME_BYTES: usize = 128;
const STP_DESTINATION: [u8; 6] = [0x01, 0x80, 0xc2, 0, 0, 0];

pub struct PreparedFrame<'a> {
    pub bytes: &'a [u8],
    pub root: BridgeId,
    source: [u8; 6],
}

pub struct Admitted<'a> {
    pub control: PreparedFrame<'a>,
    pub attack: PreparedFrame<'a>,
    pub schedule: Schedule,
}

pub fn admit<'a>(
    scenario: &Scenario<'a>,
    local_root: BridgeId,
    budget: Budget,
) -> Result<Admitted<'a>, Error> {
    let control = prepare(scenario.control)?;
    let attack = prepare(scenario.attack)?;
    validate_bridge_id(scenario.expected_root)?;
    validate_relationships(scenario, local_root, &control, &attack)?;

    // Admit both complete frames before any bridge state can change
    let stimuli = [
        Stimulus::new(
            1,
            1,
            u64::try_from(control.bytes.len()).map_err(|_| Error::Invariant)?,
        ),
        Stimulus::new(
            2,
            2,
            u64::try_from(attack.bytes.len()).map_err(|_| Error::Invariant)?,
        ),
    ];
    let schedule = Schedule::new(&stimuli, budget).map_err(Error::Admission)?;
    Ok(Admitted {
        control,
        attack,
        schedule,
    })
}

fn validate_relationships(
    scenario: &Scenario<'_>,
    local_root: BridgeId,
    control: &PreparedFrame<'_>,
    attack: &PreparedFrame<'_>,
) -> Result<(), Error> {
    if control.root != scenario.expected_root
        || !superior(control.root, local_root)
        || !superior(attack.root, control.root)
    {
        return Err(Error::InvalidScenario);
    }
    if control.source == attack.source || [control.source, attack.source].contains(&local_root.mac)
    {
        return Err(Error::InvalidScenario);
    }
    Ok(())
}

fn prepare(bytes: &[u8]) -> Result<PreparedFrame<'_>, Error> {
    let ethernet = decode_ethernet(bytes)?;
    let root = decode_root(ethernet.payload)?;
    Ok(PreparedFrame {
        bytes,
        root,
        source: ethernet.source,
    })
}

fn decode_ethernet(bytes: &[u8]) -> Result<EthernetFrame<'_>, Error> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(Error::InvalidFrame);
    }
    let ethernet = l2_core::decode(bytes).map_err(Error::Ethernet)?;
    validate_ethernet(&ethernet)?;
    Ok(ethernet)
}

fn decode_root(payload: &[u8]) -> Result<BridgeId, Error> {
    let bpdu = l2_codecs::decode_stp(payload).map_err(Error::Bpdu)?;
    validate_bpdu(&bpdu)?;
    let root = bpdu.root.ok_or(Error::InvalidFrame)?;
    let sender = bpdu.bridge.ok_or(Error::InvalidFrame)?;
    let timers = bpdu.timers.ok_or(Error::InvalidFrame)?;
    validate_timers(timers)?;
    validate_bridge_id(root)?;
    validate_bridge_id(sender)?;
    Ok(root)
}

fn validate_ethernet(ethernet: &EthernetFrame<'_>) -> Result<(), Error> {
    if ethernet.destination != STP_DESTINATION
        || !ethernet.vlan_tags.is_empty()
        || !matches!(ethernet.field, FrameField::Length(_))
        || MacAddress::new(ethernet.source).is_err()
    {
        return Err(Error::InvalidFrame);
    }
    Ok(())
}

const fn validate_bpdu(bpdu: &StpFrame<'_>) -> Result<(), Error> {
    if bpdu.llc.is_none()
        || !bpdu.padding.is_empty()
        || !matches!(
            bpdu.bpdu_type,
            StpBpduType::Configuration | StpBpduType::Rapid
        )
    {
        return Err(Error::InvalidFrame);
    }
    Ok(())
}

const fn validate_timers(timers: StpTimers) -> Result<(), Error> {
    if timers.max_age == 0
        || timers.message_age >= timers.max_age
        || timers.hello_time == 0
        || timers.forward_delay == 0
    {
        return Err(Error::InvalidFrame);
    }
    Ok(())
}

pub fn validate_bridge_id(id: BridgeId) -> Result<(), Error> {
    if id.priority & 0x0fff != 0
        || id.system_id_extension & 0xf000 != 0
        || MacAddress::new(id.mac).is_err()
    {
        return Err(Error::InvalidBridge);
    }
    Ok(())
}

pub fn superior(candidate: BridgeId, current: BridgeId) -> bool {
    (candidate.wire_priority_and_extension(), candidate.mac)
        < (current.wire_priority_and_extension(), current.mac)
}
